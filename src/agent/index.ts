import { EventEmitter } from "node:events";
import { hostname, platform, arch } from "node:os";
import { WebSocket, type RawData } from "ws";
import {
  CloseCode, HostlinkError, PROTOCOL_VERSION, SCOPE_RE, METHOD_RE, TERMINAL_CLOSE_CODES,
  cleanText, exportPrivateKey, generateDeviceKey, importPrivateKey, isPlainObject, makeAudience, normalizePrefix, signAuth,
  type AgentFrame, type DeviceInfo, type Grant, type GrantMode, type PairPollResponse, type PairStartResponse, type ServerFrame,
} from "../protocol.js";
import { VERSION } from "../version.js";
import { FileCredentialStore, MemoryCredentialStore, type CredentialStore, type StoredCredential } from "./credentials.js";
import type { KeyObject } from "node:crypto";

export { FileCredentialStore, MemoryCredentialStore, defaultCredentialPath } from "./credentials.js";
export type { CredentialStore, StoredCredential } from "./credentials.js";

export interface CallContext {
  cap: string;
  method: string;
  /** Aborted when the server cancels the call, the call times out, or the agent stops. */
  signal: AbortSignal;
}

export type CapabilityMethod = (params: any, ctx: CallContext) => unknown;

/** A set of methods the device offers. The capability name is also the scope the user approves. */
export interface Capability {
  name: string;
  methods: Record<string, CapabilityMethod>;
  /** Called when the agent stops. Release browsers, temp files, etc. */
  dispose?(): unknown;
}

export interface CallRequest { cap: string; method: string; params: unknown }

export type AgentStatus =
  | { state: "pairing"; userCode: string; verificationUri: string; verificationUriComplete: string; expiresIn: number }
  | { state: "connecting"; attempt: number }
  | { state: "online"; deviceId: string; grant: Grant }
  | { state: "reconnecting"; inMs: number; code: number; reason: string }
  | { state: "ended"; reason: string };

export interface AgentOptions {
  /** Server origin, e.g. "https://cloud.example.com". */
  server: string;
  prefix?: string;
  /** Shown to the user on the approval screen. Default: the hostname. */
  name?: string;
  mode: GrantMode;
  /** Requested lifetime in seconds; null lets the server pick its default. */
  ttlSeconds?: number | null;
  capabilities: Capability[];
  /** Where to keep the device key between runs. Default: a 0600 file for timed/trusted, memory only for once. */
  credentials?: CredentialStore;
  /** Allow http:// / ws:// to hosts other than localhost. Never do this in production. */
  allowInsecure?: boolean;
  /** Ask the local user before running a call. Return false to refuse it. */
  confirm?: (call: CallRequest) => Promise<boolean> | boolean;
  /** Called for every call, after it finishes. For local audit logs. */
  onCall?: (call: CallRequest & { ok: boolean; ms: number; error?: string }) => void;
}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
const MAX_RESULT_ERROR = 2000;

export class HostlinkAgent extends EventEmitter {
  readonly audience: string;
  private readonly origin: URL;
  private readonly prefix: string;
  private readonly opts: AgentOptions;
  private readonly caps = new Map<string, Capability>();
  private readonly credStore: CredentialStore;
  private cred: { deviceId: string; key: KeyObject; grant: Grant; persisted: boolean } | null = null;
  private ws: WebSocket | null = null;
  private stopped = false;
  private started = false;
  private stopping: Promise<void> | null = null;
  private readonly lifetime = new AbortController();
  private readonly inflight = new Map<string, AbortController>();
  private endReason: string | null = null;
  private resolveDone!: (reason: string) => void;
  /** Resolves with the reason once the agent has ended for good. */
  readonly done: Promise<string>;
  private expiryTimer: NodeJS.Timeout | null = null;

  constructor(opts: AgentOptions) {
    super();
    this.opts = opts;
    this.origin = new URL(opts.server);
    if (this.origin.protocol !== "https:" && this.origin.protocol !== "http:") throw new HostlinkError("invalid_option", "server must be an http(s) URL");
    if (this.origin.protocol === "http:" && !LOCAL_HOSTS.has(this.origin.hostname) && !opts.allowInsecure) {
      throw new HostlinkError("insecure_server", "Refusing to connect over plain http to a non-local server (use https)");
    }
    this.prefix = normalizePrefix(opts.prefix ?? "/hostlink");
    this.audience = makeAudience(opts.server, this.prefix);
    for (const c of opts.capabilities) {
      if (!SCOPE_RE.test(c.name)) throw new HostlinkError("invalid_option", `Invalid capability name "${c.name}"`);
      if (this.caps.has(c.name)) throw new HostlinkError("invalid_option", `Duplicate capability "${c.name}"`);
      for (const m of Object.keys(c.methods)) if (!METHOD_RE.test(m)) throw new HostlinkError("invalid_option", `Invalid method name "${c.name}.${m}"`);
      this.caps.set(c.name, c);
    }
    if (this.caps.size === 0) throw new HostlinkError("invalid_option", "At least one capability is required");
    this.credStore = opts.credentials ?? (opts.mode === "once" ? new MemoryCredentialStore() : new FileCredentialStore());
    this.done = new Promise((r) => { this.resolveDone = r; });
  }

  private status(s: AgentStatus) { this.emit("status", s); }

  private deviceInfo(): DeviceInfo {
    return { name: cleanText(this.opts.name, 64, cleanText(hostname(), 64, "device")), platform: platform(), arch: arch(), agentVersion: VERSION };
  }

  /** Pairs if needed, then connects. Resolves when the device is online for the first time. */
  async start(): Promise<{ deviceId: string; grant: Grant }> {
    if (this.stopped) throw new HostlinkError("stopped", "Agent was stopped");
    if (this.started) throw new HostlinkError("already_started", "start() was already called");
    this.started = true;
    const saved = await this.credStore.load(this.audience);
    if (saved && (saved.grant.expiresAt === null || saved.grant.expiresAt > Date.now())) {
      this.cred = { deviceId: saved.deviceId, key: importPrivateKey(saved.privateKey), grant: saved.grant, persisted: true };
    } else {
      if (saved) await this.credStore.delete(this.audience);
      try {
        await this.pair();
      } catch (e) {
        await this.end(`pairing failed: ${(e as Error).message}`);
        throw e;
      }
    }
    return new Promise((resolve, reject) => {
      const onStatus = (s: AgentStatus) => {
        if (s.state === "online") { cleanup(); resolve({ deviceId: s.deviceId, grant: s.grant }); }
        if (s.state === "ended") { cleanup(); reject(new HostlinkError("ended", s.reason)); }
      };
      const cleanup = () => this.off("status", onStatus);
      this.on("status", onStatus);
      this.connectLoop().catch((e) => this.end(`error: ${(e as Error).message}`));
    });
  }

  // ---------------------------------------------------------------- pairing

  private async pair() {
    const { privateKey, publicKey } = generateDeviceKey();
    const scopes = [...this.caps.keys()];
    const start = (await this.post("pair/start", {
      v: PROTOCOL_VERSION,
      publicKey,
      device: this.deviceInfo(),
      requested: { scopes, mode: this.opts.mode, ttlSeconds: this.opts.ttlSeconds ?? null },
    })) as PairStartResponse;
    this.status({ state: "pairing", userCode: start.userCode, verificationUri: start.verificationUri, verificationUriComplete: start.verificationUriComplete, expiresIn: start.expiresIn });
    const deadline = Date.now() + start.expiresIn * 1000;
    let interval = Math.max(0.05, Number(start.interval) || 5);
    let networkFailures = 0;
    while (Date.now() < deadline) {
      await sleep(interval * 1000, this.lifetime.signal);
      let r: PairPollResponse;
      try {
        r = (await this.post("pair/poll", { deviceCode: start.deviceCode })) as PairPollResponse;
        networkFailures = 0;
      } catch (e) {
        if (e instanceof HostlinkError && e.status < 500 && e.status !== 429) throw e;
        if (++networkFailures > 20) throw e;
        continue;
      }
      if (r.status === "pending") continue;
      if (r.status === "slow_down") { interval = Math.max(interval, r.interval); continue; }
      if (r.status === "denied") throw new HostlinkError("pairing_denied", "The request was denied");
      if (r.status === "expired") throw new HostlinkError("pairing_expired", "The code expired before it was approved");
      if (r.status === "approved") {
        this.cred = { deviceId: r.deviceId, key: privateKey, grant: r.grant, persisted: false };
        if (r.grant.mode !== "once") {
          await this.credStore.save({ v: 1, audience: this.audience, deviceId: r.deviceId, privateKey: exportPrivateKey(privateKey), grant: r.grant, name: this.deviceInfo().name, savedAt: Date.now() });
          this.cred.persisted = true;
        }
        return;
      }
      throw new HostlinkError("protocol_error", "Unexpected poll response");
    }
    throw new HostlinkError("pairing_expired", "The code expired before it was approved");
  }

  private async post(action: string, body: unknown): Promise<unknown> {
    const url = new URL(`${this.prefix}/v1/${action}`, this.origin);
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": `hostlink/${VERSION}` },
      body: JSON.stringify(body),
      signal: AbortSignal.any([this.lifetime.signal, AbortSignal.timeout(15_000)]),
      redirect: "error",
    });
    let data: unknown = null;
    try { data = await res.json(); } catch { /* non-JSON */ }
    if (!res.ok) {
      const d = isPlainObject(data) ? data : {};
      throw new HostlinkError(cleanText(d.error, 64, "http_error"), cleanText(d.message, 500, `Server answered ${res.status}`), res.status);
    }
    return data;
  }

  // ---------------------------------------------------------------- connection

  private async connectLoop() {
    let attempt = 0;
    while (!this.stopped) {
      attempt++;
      this.status({ state: "connecting", attempt });
      const { code, reason, wasReady } = await this.connectOnce();
      if (this.stopped) return;
      if (wasReady) attempt = 1;
      if (TERMINAL_CLOSE_CODES.has(code)) {
        await this.forget();
        return this.end(code === CloseCode.Revoked ? "revoked" : code === CloseCode.Expired ? "expired" : "unauthorized");
      }
      if (code === CloseCode.Replaced) return this.end("replaced by another connection of this device");
      if (code === CloseCode.ProtocolError) return this.end(`protocol error: ${reason}`);
      if (code === 1000) return this.end(reason || "closed by server");
      const inMs = Math.round(Math.random() * Math.min(30_000, 1000 * 2 ** Math.min(attempt, 5)));
      this.status({ state: "reconnecting", inMs, code, reason });
      try { await sleep(inMs, this.lifetime.signal); } catch { return; }
    }
  }

  private connectOnce(): Promise<{ code: number; reason: string; wasReady: boolean }> {
    const cred = this.cred!;
    const wsUrl = new URL(`${this.prefix}/v1/connect`, this.origin);
    wsUrl.protocol = this.origin.protocol === "https:" ? "wss:" : "ws:";
    return new Promise((resolve) => {
      let wasReady = false;
      let settled = false;
      const ws = new WebSocket(wsUrl, { handshakeTimeout: 15_000, maxPayload: 64 * 1024 * 1024, followRedirects: false, headers: { "user-agent": `hostlink/${VERSION}` } });
      this.ws = ws;
      let pingWatch: NodeJS.Timeout | null = null;
      const armWatch = () => {
        if (pingWatch) clearTimeout(pingWatch);
        // Server pings every ~20s; if we hear nothing for 75s the link is dead.
        pingWatch = setTimeout(() => ws.terminate(), 75_000);
      };
      const finish = (code: number, reason: string) => {
        if (settled) return;
        settled = true;
        if (pingWatch) clearTimeout(pingWatch);
        if (this.ws === ws) this.ws = null;
        for (const ac of this.inflight.values()) ac.abort();
        this.inflight.clear();
        resolve({ code, reason, wasReady });
      };
      ws.on("open", armWatch);
      ws.on("ping", armWatch);
      ws.on("error", () => { /* close follows */ });
      ws.on("close", (code, reason) => finish(code, reason.toString()));
      ws.on("unexpected-response", (_req, res) => { finish(1006, `HTTP ${res.statusCode}`); ws.terminate(); });
      ws.on("message", (raw: RawData, isBinary: boolean) => {
        armWatch();
        let f: ServerFrame;
        try {
          if (isBinary) throw new Error("binary");
          f = JSON.parse(raw.toString()) as ServerFrame;
          if (!isPlainObject(f)) throw new Error("shape");
        } catch {
          ws.close(CloseCode.ProtocolError, "bad frame");
          return;
        }
        if (f.t === "challenge") {
          if (wasReady || typeof f.nonce !== "string" || f.nonce.length < 32 || f.nonce.length > 128) { ws.close(CloseCode.ProtocolError, "bad challenge"); return; }
          if (f.v !== PROTOCOL_VERSION) { ws.close(CloseCode.ProtocolError, "unsupported version"); return; }
          send(ws, {
            t: "auth", v: PROTOCOL_VERSION, deviceId: cred.deviceId,
            sig: signAuth(cred.key, this.audience, cred.deviceId, f.nonce),
            capabilities: [...this.caps.values()].map((c) => ({ name: c.name, methods: Object.keys(c.methods) })),
            device: this.deviceInfo(),
          });
          return;
        }
        if (f.t === "ready") {
          if (f.deviceId !== cred.deviceId) { ws.close(CloseCode.ProtocolError, "wrong device"); return; }
          wasReady = true;
          cred.grant = f.grant;
          this.armExpiry(f.grant);
          this.status({ state: "online", deviceId: cred.deviceId, grant: f.grant });
          return;
        }
        if (!wasReady) { ws.close(CloseCode.ProtocolError, "not ready"); return; }
        if (f.t === "call") { void this.handleCall(ws, f); return; }
        if (f.t === "cancel") { if (typeof f.id === "string") this.inflight.get(f.id)?.abort(); return; }
      });
    });
  }

  private armExpiry(grant: Grant) {
    if (this.expiryTimer) clearTimeout(this.expiryTimer);
    this.expiryTimer = null;
    if (grant.expiresAt === null) return;
    const ms = grant.expiresAt - Date.now();
    // setTimeout cannot wait more than ~24.8 days; re-arm in steps.
    this.expiryTimer = setTimeout(() => {
      if (grant.expiresAt !== null && grant.expiresAt <= Date.now()) void this.forget().then(() => this.stop("expired"));
      else this.armExpiry(grant);
    }, Math.max(0, Math.min(ms, 2 ** 31 - 1)));
    this.expiryTimer.unref();
  }

  private async handleCall(ws: WebSocket, f: Extract<ServerFrame, { t: "call" }>) {
    const id = typeof f.id === "string" && f.id.length <= 64 ? f.id : null;
    if (!id) return;
    const reply = (frame: AgentFrame) => { if (ws.readyState === WebSocket.OPEN) send(ws, frame); };
    const fail = (code: string, message: string) => reply({ t: "result", id, ok: false, error: { code, message: message.slice(0, MAX_RESULT_ERROR) } });
    const capName = typeof f.cap === "string" ? f.cap : "";
    const methodName = typeof f.method === "string" ? f.method : "";
    const cap = this.caps.get(capName);
    // Local enforcement: the device only runs what it offers AND what the user granted.
    if (!cap || !Object.hasOwn(cap.methods, methodName) || typeof cap.methods[methodName] !== "function") return fail("method_not_supported", `${capName}.${methodName} is not offered by this device`);
    if (!this.cred?.grant.scopes.includes(capName)) return fail("scope_not_granted", `Scope "${capName}" was not granted`);
    if (this.inflight.has(id)) return fail("duplicate_call", "Duplicate call id");
    const ac = new AbortController();
    this.inflight.set(id, ac);
    const started = Date.now();
    const req: CallRequest = { cap: capName, method: methodName, params: f.params };
    try {
      if (this.opts.confirm && !(await this.opts.confirm(req))) throw new HostlinkError("denied_by_user", "The person at the device refused this action");
      if (ac.signal.aborted) throw new HostlinkError("aborted", "Call was cancelled");
      const value = await cap.methods[methodName]!(f.params, { cap: capName, method: methodName, signal: ac.signal });
      if (ac.signal.aborted) return; // server already gave up
      let text: string;
      try { text = JSON.stringify({ t: "result", id, ok: true, value: value === undefined ? null : value }); }
      catch { throw new HostlinkError("unserialisable_result", "Result could not be encoded as JSON"); }
      if (ws.readyState === WebSocket.OPEN) ws.send(text, () => {});
      this.opts.onCall?.({ ...req, ok: true, ms: Date.now() - started });
    } catch (e) {
      const err = e as { code?: unknown; message?: unknown; name?: unknown };
      const code = typeof err.code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(err.code) ? err.code : err.name === "TimeoutError" ? "timeout" : "error";
      const message = typeof err.message === "string" ? err.message : String(e);
      if (!ac.signal.aborted) fail(code, message);
      this.opts.onCall?.({ ...req, ok: false, ms: Date.now() - started, error: message });
    } finally {
      this.inflight.delete(id);
    }
  }

  // ---------------------------------------------------------------- shutdown

  /** Removes the saved credential for this server. */
  async forget(): Promise<void> {
    await this.credStore.delete(this.audience);
    if (this.cred) this.cred.persisted = false;
  }

  /** Stops the agent. In "once" mode this also ends the link on the server. */
  stop(reason = "stopped"): Promise<void> {
    if (this.stopping) return this.stopping;
    this.stopping = (async () => {
      this.stopped = true;
      const ws = this.ws;
      if (ws && ws.readyState === WebSocket.OPEN && this.cred?.grant.mode === "once") {
        send(ws, { t: "bye" });
        await waitClose(ws, 2000);
      }
      this.lifetime.abort();
      if (ws && ws.readyState !== WebSocket.CLOSED) {
        ws.close(1000, "agent stopped");
        await waitClose(ws, 2000);
      }
      await this.end(reason);
    })();
    return this.stopping;
  }

  private async end(reason: string) {
    if (this.endReason !== null) return;
    this.endReason = reason;
    this.stopped = true;
    this.lifetime.abort();
    if (this.expiryTimer) clearTimeout(this.expiryTimer);
    if (this.ws) this.ws.close(1000, "agent ended");
    for (const c of this.caps.values()) {
      try { await c.dispose?.(); } catch (e) { this.emit("error", e); }
    }
    this.status({ state: "ended", reason });
    this.resolveDone(reason);
  }
}

function send(ws: WebSocket, frame: AgentFrame) {
  ws.send(JSON.stringify(frame), () => {});
}

function waitClose(ws: WebSocket, ms: number): Promise<void> {
  return new Promise((r) => {
    if (ws.readyState === WebSocket.CLOSED) return r();
    const t = setTimeout(r, ms);
    ws.once("close", () => { clearTimeout(t); r(); });
  });
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(new HostlinkError("stopped", "Agent stopped"));
    const t = setTimeout(() => { signal.removeEventListener("abort", onAbort); resolve(); }, ms);
    const onAbort = () => { clearTimeout(t); reject(new HostlinkError("stopped", "Agent stopped")); };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}
