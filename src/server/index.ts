import { EventEmitter } from "node:events";
import type { IncomingMessage, Server as HttpServer, ServerResponse } from "node:http";
import type { Duplex } from "node:stream";
import { WebSocketServer, WebSocket, type RawData } from "ws";
import {
  CloseCode, GRANT_MODES, HostlinkError, METHOD_RE, PROTOCOL_VERSION, SCOPE_RE,
  cleanText, generateUserCode, isPlainObject, makeAudience, normalizePrefix, normalizeUserCode,
  publicKeyFromRaw, randomToken, sha256, verifyAuth,
  type AgentFrame, type CapabilityDescriptor, type DeviceInfo, type Grant, type GrantMode,
  type PairPollResponse, type PairStartResponse, type ServerFrame,
} from "../protocol.js";
import { MemoryStore, type DeviceRecord, type HostlinkStore, type PairingRecord } from "./store.js";

export { MemoryStore, FileStore } from "./store.js";
export type { HostlinkStore, DeviceRecord, PairingRecord, PairingStatus } from "./store.js";
export { HostlinkError, CloseCode } from "../protocol.js";
export type { Grant, GrantMode, CapabilityDescriptor, DeviceInfo } from "../protocol.js";

const HOUR = 3600;
const DAY = 86400;

export interface HostlinkPolicy {
  /** Capability names devices may request. null = any well-formed name. */
  allowedScopes: string[] | null;
  pairingTtlSeconds: number;
  pollIntervalSeconds: number;
  onceMaxTtlSeconds: number;
  /** A "once" device that stays disconnected this long is removed. */
  onceDisconnectGraceSeconds: number;
  timedDefaultTtlSeconds: number;
  timedMaxTtlSeconds: number;
  trustedDefaultTtlSeconds: number;
  trustedMaxTtlSeconds: number;
  /** Allow grants that never expire (trusted mode with ttl null). Off by default. */
  allowLifetime: boolean;
  callTimeoutMs: number;
  maxCallTimeoutMs: number;
  maxInFlightPerDevice: number;
  maxPayloadBytes: number;
  pairStartsPerIpPerMinute: number;
  approveFailuresPerOwnerPer10Min: number;
  authTimeoutMs: number;
  heartbeatMs: number;
}

export const DEFAULT_POLICY: HostlinkPolicy = {
  allowedScopes: null,
  pairingTtlSeconds: 600,
  pollIntervalSeconds: 3,
  onceMaxTtlSeconds: 12 * HOUR,
  onceDisconnectGraceSeconds: 120,
  timedDefaultTtlSeconds: 24 * HOUR,
  timedMaxTtlSeconds: 30 * DAY,
  trustedDefaultTtlSeconds: 90 * DAY,
  trustedMaxTtlSeconds: 90 * DAY,
  allowLifetime: false,
  callTimeoutMs: 60_000,
  maxCallTimeoutMs: 10 * 60_000,
  maxInFlightPerDevice: 16,
  maxPayloadBytes: 32 * 1024 * 1024,
  pairStartsPerIpPerMinute: 10,
  approveFailuresPerOwnerPer10Min: 10,
  authTimeoutMs: 10_000,
  heartbeatMs: 20_000,
};

export interface HostlinkServerOptions {
  /** Public origin agents connect to, e.g. "https://cloud.example.com". Part of the signed audience. */
  publicUrl: string;
  /** Path prefix for the HTTP and WebSocket endpoints. Default "/hostlink". */
  prefix?: string;
  /** Page in YOUR app where a signed-in user types the code. "?code=XXXX-XXXX" is appended for the direct link. */
  verificationUri: string;
  store?: HostlinkStore;
  policy?: Partial<HostlinkPolicy>;
  /** Read client IPs from X-Forwarded-For (only when behind a proxy you control). */
  trustProxy?: boolean;
  /** Housekeeping interval. 0 disables the timer (call sweep() yourself). Default 30000. */
  sweepIntervalMs?: number;
  /** Clock, for tests. */
  now?: () => number;
}

export interface PairingDescription {
  userCode: string;
  device: DeviceInfo;
  ip: string;
  requested: { scopes: string[]; mode: GrantMode; ttlSeconds: number | null };
  expiresAt: number;
}

export interface ApproveOptions {
  userCode: string;
  /** The signed-in user approving. Becomes the device owner. */
  ownerId: string;
  /** Narrow the requested scopes. Must be a subset of what the device asked for. */
  scopes?: string[];
  mode?: GrantMode;
  /** Seconds, or null for lifetime (needs policy.allowLifetime). */
  ttlSeconds?: number | null;
}

export interface DeviceView {
  id: string;
  ownerId: string;
  device: DeviceInfo;
  grant: Grant;
  pairedAt: number;
  pairedFromIp: string;
  lastSeenAt: number;
  lastSeenIp: string | null;
  online: boolean;
  capabilities: CapabilityDescriptor[];
}

export interface CallOptions {
  ownerId: string;
  deviceId: string;
  cap: string;
  method: string;
  params?: unknown;
  timeoutMs?: number;
  signal?: AbortSignal;
}

interface Pending {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
  cleanup: () => void;
}

interface Session {
  id: string;
  ws: WebSocket;
  deviceId: string;
  ownerId: string;
  grant: Grant;
  capabilities: CapabilityDescriptor[];
  pending: Map<string, Pending>;
  alive: boolean;
}

class WindowLimiter {
  private hits = new Map<string, { n: number; resetAt: number }>();
  constructor(private readonly limit: number, private readonly windowMs: number) {}
  /** Returns false once the limit is reached within the window. */
  hit(key: string, now: number): boolean {
    const e = this.hits.get(key);
    if (!e || e.resetAt <= now) {
      this.hits.set(key, { n: 1, resetAt: now + this.windowMs });
      return true;
    }
    e.n++;
    return e.n <= this.limit;
  }
  blocked(key: string, now: number): boolean {
    const e = this.hits.get(key);
    return !!e && e.resetAt > now && e.n >= this.limit;
  }
  prune(now: number) {
    for (const [k, e] of this.hits) if (e.resetAt <= now) this.hits.delete(k);
  }
}

const MAX_BODY = 16 * 1024;

export class HostlinkServer extends EventEmitter {
  readonly audience: string;
  readonly prefix: string;
  readonly policy: HostlinkPolicy;
  readonly store: HostlinkStore;
  private readonly verificationUri: string;
  private readonly trustProxy: boolean;
  private readonly now: () => number;
  private readonly wss: WebSocketServer;
  private readonly sessions = new Map<string, Session>();
  /** Sockets that passed the signature check but are not ready yet, by device id. */
  private readonly authing = new Map<string, Set<WebSocket>>();
  private readonly startLimiter: WindowLimiter;
  private readonly approveLimiter: WindowLimiter;
  private sweepTimer: NodeJS.Timeout | null = null;
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private closed = false;

  constructor(opts: HostlinkServerOptions) {
    super();
    const u = new URL(opts.publicUrl);
    if (u.protocol !== "https:" && u.protocol !== "http:") throw new HostlinkError("invalid_option", "publicUrl must be http(s)");
    this.prefix = normalizePrefix(opts.prefix ?? "/hostlink");
    this.audience = makeAudience(opts.publicUrl, this.prefix);
    new URL(opts.verificationUri); // validates
    this.verificationUri = opts.verificationUri;
    this.policy = validatePolicy({ ...DEFAULT_POLICY, ...opts.policy });
    this.store = opts.store ?? new MemoryStore();
    this.trustProxy = !!opts.trustProxy;
    this.now = opts.now ?? Date.now;
    this.startLimiter = new WindowLimiter(this.policy.pairStartsPerIpPerMinute, 60_000);
    this.approveLimiter = new WindowLimiter(this.policy.approveFailuresPerOwnerPer10Min, 600_000);
    this.wss = new WebSocketServer({ noServer: true, maxPayload: this.policy.maxPayloadBytes });
    const sweepMs = opts.sweepIntervalMs ?? 30_000;
    if (sweepMs > 0) {
      this.sweepTimer = setInterval(() => void this.sweep().catch((e) => this.emit("error", e)), sweepMs);
      this.sweepTimer.unref();
    }
    this.heartbeatTimer = setInterval(() => this.heartbeat(), this.policy.heartbeatMs);
    this.heartbeatTimer.unref();
  }

  /** Adds request + upgrade listeners to a Node HTTP server. Requests outside the prefix are left alone. */
  attach(server: HttpServer): this {
    server.on("upgrade", (req, socket, head) => {
      if (!this.handleUpgrade(req, socket, head) && server.listenerCount("upgrade") === 1) socket.destroy();
    });
    return this;
  }

  // ------------------------------------------------------------------ HTTP

  /** Handles the pairing endpoints. Resolves true if the request was ours. */
  async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
    const path = (req.url ?? "").split("?")[0] ?? "";
    const base = `${this.prefix}/v1/pair/`;
    if (!path.startsWith(base)) return false;
    const action = path.slice(base.length);
    if (action !== "start" && action !== "poll") return false;
    try {
      if (req.method !== "POST") throw new HostlinkError("method_not_allowed", "Use POST", 405);
      const ct = (req.headers["content-type"] ?? "").split(";")[0]!.trim().toLowerCase();
      if (ct !== "application/json") throw new HostlinkError("unsupported_media_type", "Content-Type must be application/json", 415);
      const body = await readJson(req);
      const ip = this.clientIp(req);
      const out = action === "start" ? await this.pairStart(body, ip) : await this.pairPoll(body);
      sendJson(res, 200, out);
    } catch (e) {
      const err = e instanceof HostlinkError ? e : new HostlinkError("internal_error", "Internal error", 500);
      if (!(e instanceof HostlinkError)) this.emit("error", e);
      sendJson(res, err.status, { error: err.code, message: err.message });
    }
    return true;
  }

  private async pairStart(body: unknown, ip: string): Promise<PairStartResponse> {
    const now = this.now();
    if (!this.startLimiter.hit(ip, now)) throw new HostlinkError("rate_limited", "Too many pairing requests, try again in a minute", 429);
    if (!isPlainObject(body)) throw new HostlinkError("invalid_request", "Body must be a JSON object");
    if (body.v !== PROTOCOL_VERSION) throw new HostlinkError("unsupported_version", `Protocol version ${PROTOCOL_VERSION} required`);
    if (typeof body.publicKey !== "string") throw new HostlinkError("invalid_public_key", "publicKey required");
    publicKeyFromRaw(body.publicKey);
    const device = parseDeviceInfo(body.device);
    const r = body.requested;
    if (!isPlainObject(r)) throw new HostlinkError("invalid_request", "requested required");
    const requested = {
      scopes: parseScopes(r.scopes),
      mode: parseMode(r.mode),
      ttlSeconds: r.ttlSeconds === null || r.ttlSeconds === undefined ? null : parseTtl(r.ttlSeconds),
    };
    // Validate up front so the device learns about policy problems before the user is involved.
    this.resolveGrant(requested, {}, now);

    const deviceCode = randomToken(32);
    let userCode = "";
    for (let i = 0; i < 8; i++) {
      const candidate = generateUserCode();
      if (!(await this.store.findPairingByUserCode(sha256(candidate)))) { userCode = candidate; break; }
    }
    if (!userCode) throw new HostlinkError("internal_error", "Could not allocate a code", 503);
    const rec: PairingRecord = {
      id: randomToken(12),
      deviceCodeHash: sha256(deviceCode),
      userCodeHash: sha256(userCode),
      publicKey: body.publicKey,
      device,
      ip,
      requested,
      status: "pending",
      createdAt: now,
      expiresAt: now + this.policy.pairingTtlSeconds * 1000,
      interval: this.policy.pollIntervalSeconds,
      lastPolledAt: null,
    };
    await this.store.createPairing(rec);
    const sep = this.verificationUri.includes("?") ? "&" : "?";
    return {
      deviceCode,
      userCode,
      verificationUri: this.verificationUri,
      verificationUriComplete: `${this.verificationUri}${sep}code=${encodeURIComponent(userCode)}`,
      expiresIn: this.policy.pairingTtlSeconds,
      interval: rec.interval,
    };
  }

  private async pairPoll(body: unknown): Promise<PairPollResponse> {
    if (!isPlainObject(body) || typeof body.deviceCode !== "string" || body.deviceCode.length > 128) {
      throw new HostlinkError("invalid_request", "deviceCode required");
    }
    const now = this.now();
    const p = await this.store.findPairingByDeviceCode(sha256(body.deviceCode));
    if (!p) return { status: "expired" };
    if (p.status === "approved" && p.deviceId && p.grant && p.ownerId) {
      const rec: DeviceRecord = {
        id: p.deviceId,
        ownerId: p.ownerId,
        publicKey: p.publicKey,
        device: p.device,
        grant: p.grant,
        pairedAt: now,
        pairedFromIp: p.ip,
        lastSeenAt: now,
        lastSeenIp: null,
      };
      // putDevice is idempotent, so a concurrent second poll yields the same device.
      await this.store.putDevice(rec);
      await this.store.deletePairing(p.id);
      this.emit("device:paired", this.view(rec));
      return { status: "approved", deviceId: rec.id, grant: rec.grant };
    }
    if (p.expiresAt <= now) {
      await this.store.deletePairing(p.id);
      return { status: "expired" };
    }
    if (p.status === "denied") {
      await this.store.deletePairing(p.id);
      return { status: "denied" };
    }
    if (p.lastPolledAt !== null && now - p.lastPolledAt < p.interval * 1000 - 500) {
      const interval = Math.min(p.interval + 5, 60);
      await this.store.touchPairing(p.id, { lastPolledAt: now, interval });
      return { status: "slow_down", interval };
    }
    await this.store.touchPairing(p.id, { lastPolledAt: now, interval: p.interval });
    return { status: "pending" };
  }

  // ------------------------------------------------------------------ approval (called by YOUR authenticated routes)

  /** Details to show the user before they approve. Null if the code is unknown, used or expired. */
  async describePairing(userCode: string): Promise<PairingDescription | null> {
    const p = await this.findPending(userCode);
    if (!p) return null;
    return { userCode: normalizeUserCode(userCode)!, device: p.device, ip: p.ip, requested: p.requested, expiresAt: p.expiresAt };
  }

  async approve(opts: ApproveOptions): Promise<{ deviceId: string; grant: Grant; device: DeviceInfo }> {
    const ownerId = requireOwner(opts.ownerId);
    const p = await this.pendingForOwner(opts.userCode, ownerId);
    const overrides: { scopes?: string[]; mode?: GrantMode; ttlSeconds?: number | null } = {};
    if (opts.scopes !== undefined) overrides.scopes = parseScopes(opts.scopes);
    if (opts.mode !== undefined) overrides.mode = parseMode(opts.mode);
    if (opts.ttlSeconds !== undefined) overrides.ttlSeconds = opts.ttlSeconds === null ? null : parseTtl(opts.ttlSeconds);
    const grant = this.resolveGrant(p.requested, overrides, this.now());
    const deviceId = `dev_${randomToken(16)}`;
    const updated = await this.store.updatePairingIf(p.id, "pending", { status: "approved", ownerId, deviceId, grant });
    if (!updated) throw new HostlinkError("already_handled", "This code was already approved or denied", 409);
    return { deviceId, grant, device: p.device };
  }

  async deny(opts: { userCode: string; ownerId: string }): Promise<void> {
    const ownerId = requireOwner(opts.ownerId);
    const p = await this.pendingForOwner(opts.userCode, ownerId);
    if (!(await this.store.updatePairingIf(p.id, "pending", { status: "denied" }))) {
      throw new HostlinkError("already_handled", "This code was already approved or denied", 409);
    }
  }

  private async pendingForOwner(userCode: string, ownerId: string): Promise<PairingRecord> {
    const now = this.now();
    if (this.approveLimiter.blocked(ownerId, now)) throw new HostlinkError("rate_limited", "Too many wrong codes, wait a few minutes", 429);
    const p = await this.findPending(userCode);
    if (!p) {
      this.approveLimiter.hit(ownerId, now);
      throw new HostlinkError("invalid_code", "That code is wrong or has expired", 404);
    }
    return p;
  }

  private async findPending(userCode: string): Promise<PairingRecord | null> {
    if (typeof userCode !== "string") return null;
    const code = normalizeUserCode(userCode);
    if (!code) return null;
    const p = await this.store.findPairingByUserCode(sha256(code));
    if (!p || p.status !== "pending" || p.expiresAt <= this.now()) return null;
    return p;
  }

  /** Applies policy to a request plus approver overrides. Throws on anything out of policy. */
  private resolveGrant(
    requested: { scopes: string[]; mode: GrantMode; ttlSeconds: number | null },
    o: { scopes?: string[]; mode?: GrantMode; ttlSeconds?: number | null },
    now: number,
  ): Grant {
    const scopes = o.scopes ?? requested.scopes;
    if (scopes.length === 0) throw new HostlinkError("invalid_scope", "At least one scope is required");
    for (const s of scopes) {
      if (!requested.scopes.includes(s)) throw new HostlinkError("invalid_scope", `Scope "${s}" was not requested by the device`);
      if (this.policy.allowedScopes && !this.policy.allowedScopes.includes(s)) throw new HostlinkError("invalid_scope", `Scope "${s}" is not allowed on this server`);
    }
    const mode = o.mode ?? requested.mode;
    const ttl = o.ttlSeconds !== undefined ? o.ttlSeconds : requested.ttlSeconds;
    const P = this.policy;
    let seconds: number | null;
    if (mode === "once") {
      if (ttl === null) seconds = P.onceMaxTtlSeconds;
      else if (ttl > P.onceMaxTtlSeconds) throw new HostlinkError("invalid_ttl", `A one-time link can last at most ${P.onceMaxTtlSeconds}s`);
      else seconds = ttl;
    } else if (mode === "timed") {
      if (ttl === null) seconds = P.timedDefaultTtlSeconds;
      else if (ttl > P.timedMaxTtlSeconds) throw new HostlinkError("invalid_ttl", `A timed link can last at most ${P.timedMaxTtlSeconds}s`);
      else seconds = ttl;
    } else {
      if (ttl === null) {
        // Requests without a TTL get the default. A lifetime grant must be asked for explicitly by the approver.
        if (o.ttlSeconds === null) {
          if (!P.allowLifetime) throw new HostlinkError("invalid_ttl", "Lifetime links are disabled on this server");
          seconds = null;
        } else seconds = P.trustedDefaultTtlSeconds;
      } else if (ttl > P.trustedMaxTtlSeconds) throw new HostlinkError("invalid_ttl", `A trusted link can last at most ${P.trustedMaxTtlSeconds}s`);
      else seconds = ttl;
    }
    return { scopes: [...new Set(scopes)], mode, expiresAt: seconds === null ? null : now + seconds * 1000 };
  }

  // ------------------------------------------------------------------ devices

  async listDevices(ownerId: string): Promise<DeviceView[]> {
    requireOwner(ownerId);
    const now = this.now();
    const out: DeviceView[] = [];
    for (const d of await this.store.listDevices({ ownerId })) {
      if (this.isExpired(d, now)) { await this.removeDevice(d.id, CloseCode.Expired, "expired"); continue; }
      out.push(this.view(d));
    }
    return out;
  }

  async getDevice(ownerId: string, deviceId: string): Promise<DeviceView | null> {
    requireOwner(ownerId);
    const d = await this.store.getDevice(String(deviceId));
    if (!d || d.ownerId !== ownerId) return null;
    if (this.isExpired(d, this.now())) { await this.removeDevice(d.id, CloseCode.Expired, "expired"); return null; }
    return this.view(d);
  }

  isOnline(deviceId: string): boolean {
    return this.sessions.has(deviceId);
  }

  /** Removes the device and disconnects it at once. Returns false if it was not found for this owner. */
  async revoke(opts: { ownerId: string; deviceId: string }): Promise<boolean> {
    const ownerId = requireOwner(opts.ownerId);
    const d = await this.store.getDevice(String(opts.deviceId));
    if (!d || d.ownerId !== ownerId) return false;
    await this.removeDevice(d.id, CloseCode.Revoked, "revoked");
    return true;
  }

  private async removeDevice(deviceId: string, code: number, reason: string) {
    for (const ws of this.authing.get(deviceId) ?? []) ws.close(code, reason);
    const removed = await this.store.deleteDevice(deviceId);
    for (const ws of this.authing.get(deviceId) ?? []) ws.close(code, reason);
    const s = this.sessions.get(deviceId);
    if (s) {
      this.sessions.delete(deviceId);
      this.failPending(s, new HostlinkError("device_offline", `Device ${reason}`, 409));
      s.ws.close(code, reason);
      this.emit("device:offline", { deviceId, ownerId: s.ownerId });
    }
    if (removed) this.emit("device:revoked", { deviceId, reason });
  }

  private isExpired(d: { grant: Grant; lastSeenAt: number; id: string }, now: number): boolean {
    if (d.grant.expiresAt !== null && d.grant.expiresAt <= now) return true;
    if (d.grant.mode === "once" && !this.sessions.has(d.id) && now - d.lastSeenAt > this.policy.onceDisconnectGraceSeconds * 1000) return true;
    return false;
  }

  private view(d: DeviceRecord): DeviceView {
    const s = this.sessions.get(d.id);
    return {
      id: d.id, ownerId: d.ownerId, device: d.device, grant: d.grant,
      pairedAt: d.pairedAt, pairedFromIp: d.pairedFromIp, lastSeenAt: d.lastSeenAt, lastSeenIp: d.lastSeenIp,
      online: !!s, capabilities: s ? s.capabilities : [],
    };
  }

  // ------------------------------------------------------------------ calls

  /** Runs `cap.method(params)` on the device and resolves with its result. */
  async call<T = unknown>(opts: CallOptions): Promise<T> {
    const ownerId = requireOwner(opts.ownerId);
    const s = this.sessions.get(String(opts.deviceId));
    if (!s || s.ownerId !== ownerId) {
      const d = s ? null : await this.store.getDevice(String(opts.deviceId));
      if (d && d.ownerId === ownerId && !this.isExpired(d, this.now())) throw new HostlinkError("device_offline", "Device is not connected", 409);
      throw new HostlinkError("device_not_found", "No such device", 404);
    }
    if (s.grant.expiresAt !== null && s.grant.expiresAt <= this.now()) {
      await this.removeDevice(s.deviceId, CloseCode.Expired, "expired");
      throw new HostlinkError("grant_expired", "The link to this device has expired", 410);
    }
    if (!s.grant.scopes.includes(opts.cap)) throw new HostlinkError("scope_not_granted", `Scope "${opts.cap}" was not granted for this device`, 403);
    const cap = s.capabilities.find((c) => c.name === opts.cap);
    if (!cap || !cap.methods.includes(opts.method)) throw new HostlinkError("method_not_supported", `Device does not offer ${opts.cap}.${opts.method}`, 501);
    if (s.pending.size >= this.policy.maxInFlightPerDevice) throw new HostlinkError("device_busy", "Too many calls in flight for this device", 429);
    if (opts.signal?.aborted) throw new HostlinkError("aborted", "Call aborted", 499);

    const id = randomToken(12);
    let frame: string;
    try {
      frame = JSON.stringify({ t: "call", id, cap: opts.cap, method: opts.method, params: opts.params ?? null } satisfies ServerFrame);
    } catch {
      throw new HostlinkError("invalid_params", "params must be JSON-serialisable");
    }
    if (Buffer.byteLength(frame) > this.policy.maxPayloadBytes) throw new HostlinkError("payload_too_large", "params too large", 413);
    const timeoutMs = Math.min(Math.max(1, opts.timeoutMs ?? this.policy.callTimeoutMs), this.policy.maxCallTimeoutMs);

    return new Promise<T>((resolve, reject) => {
      const onAbort = () => finish(new HostlinkError("aborted", "Call aborted", 499), true);
      const finish = (err: Error | null, cancel: boolean, value?: unknown) => {
        const p = s.pending.get(id);
        if (!p) return;
        p.cleanup();
        s.pending.delete(id);
        if (cancel) safeSend(s.ws, { t: "cancel", id });
        if (err) reject(err);
        else resolve(value as T);
      };
      const timer = setTimeout(() => finish(new HostlinkError("timeout", `Device did not answer within ${timeoutMs}ms`, 504), true), timeoutMs);
      s.pending.set(id, {
        resolve: (v) => finish(null, false, v),
        reject: (e) => finish(e, false),
        timer,
        cleanup: () => { clearTimeout(timer); opts.signal?.removeEventListener("abort", onAbort); },
      });
      opts.signal?.addEventListener("abort", onAbort, { once: true });
      s.ws.send(frame, (err) => { if (err) finish(new HostlinkError("device_offline", "Device connection failed", 409), false); });
    });
  }

  // ------------------------------------------------------------------ WebSocket

  /** Handles the agent WebSocket upgrade. Returns false if the URL is not ours. */
  handleUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): boolean {
    const path = (req.url ?? "").split("?")[0];
    if (path !== `${this.prefix}/v1/connect`) return false;
    if (this.closed) { socket.destroy(); return true; }
    const ip = this.clientIp(req);
    this.wss.handleUpgrade(req, socket, head, (ws) => this.onConnection(ws, ip));
    return true;
  }

  private onConnection(ws: WebSocket, ip: string) {
    const nonce = randomToken(32);
    let state: "auth" | "verifying" | "ready" | "closed" = "auth";
    let session: Session | null = null;
    const authTimer = setTimeout(() => { if (state !== "ready") ws.close(CloseCode.AuthTimeout, "auth timeout"); }, this.policy.authTimeoutMs);

    ws.on("error", () => {});
    ws.on("close", () => {
      state = "closed";
      clearTimeout(authTimer);
      if (session && this.sessions.get(session.deviceId) === session) {
        this.sessions.delete(session.deviceId);
        this.failPending(session, new HostlinkError("device_offline", "Device disconnected", 409));
        const s = session;
        void this.store.updateDevice(s.deviceId, { lastSeenAt: this.now() }).catch((e) => this.emit("error", e));
        this.emit("device:offline", { deviceId: s.deviceId, ownerId: s.ownerId });
      }
    });
    ws.on("pong", () => { if (session) session.alive = true; });
    ws.on("message", (raw: RawData, isBinary: boolean) => {
      let frame: AgentFrame;
      try {
        if (isBinary) throw new Error("binary");
        frame = JSON.parse(raw.toString()) as AgentFrame;
        if (!isPlainObject(frame)) throw new Error("shape");
      } catch {
        ws.close(CloseCode.ProtocolError, "bad frame");
        return;
      }
      if (state === "auth") {
        state = "verifying";
        this.authenticate(ws, ip, nonce, frame).then((s) => {
          if (!s) return;
          if (ws.readyState !== WebSocket.OPEN) return; // went away while we verified
          clearTimeout(authTimer);
          const prev = this.sessions.get(s.deviceId);
          if (prev) {
            this.sessions.delete(s.deviceId);
            this.failPending(prev, new HostlinkError("device_offline", "Device reconnected", 409));
            prev.ws.close(CloseCode.Replaced, "replaced by a newer connection");
          }
          session = s;
          state = "ready";
          this.sessions.set(s.deviceId, s);
          safeSend(ws, { t: "ready", sessionId: s.id, deviceId: s.deviceId, grant: s.grant });
          this.emit("device:online", { deviceId: s.deviceId, ownerId: s.ownerId, capabilities: s.capabilities });
        }).catch((e) => {
          this.emit("error", e);
          ws.close(1011, "internal error");
        });
        return;
      }
      if (state !== "ready" || !session) { ws.close(CloseCode.ProtocolError, "unexpected frame"); return; }
      this.onAgentFrame(session, frame);
    });
    safeSend(ws, { t: "challenge", v: PROTOCOL_VERSION, nonce });
  }

  private async authenticate(ws: WebSocket, ip: string, nonce: string, f: AgentFrame): Promise<Session | null> {
    const deny = (code: number, reason: string) => { ws.close(code, reason); return null; };
    if (f.t !== "auth") return deny(CloseCode.ProtocolError, "expected auth");
    if (f.v !== PROTOCOL_VERSION) return deny(CloseCode.ProtocolError, "unsupported version");
    if (typeof f.deviceId !== "string" || f.deviceId.length > 64 || typeof f.sig !== "string" || f.sig.length > 200) return deny(CloseCode.Unauthorized, "unauthorized");
    let capabilities: CapabilityDescriptor[];
    let info: DeviceInfo;
    try {
      capabilities = parseCapabilities(f.capabilities);
      info = parseDeviceInfo(f.device);
    } catch {
      return deny(CloseCode.ProtocolError, "bad capabilities");
    }
    const d = await this.store.getDevice(f.deviceId);
    if (!d) return deny(CloseCode.Unauthorized, "unauthorized");
    if (!verifyAuth(publicKeyFromRaw(d.publicKey), this.audience, d.id, nonce, f.sig)) return deny(CloseCode.Unauthorized, "unauthorized");
    const now = this.now();
    if (this.isExpired(d, now)) {
      await this.removeDevice(d.id, CloseCode.Expired, "expired");
      return deny(CloseCode.Expired, "expired");
    }
    // From here a revoke must also reach this socket, even though it is not a session yet.
    let set = this.authing.get(d.id);
    if (!set) this.authing.set(d.id, (set = new Set()));
    set.add(ws);
    try {
      // The approved name stays; version details may change between agent upgrades.
      await this.store.updateDevice(d.id, { lastSeenAt: now, lastSeenIp: ip, device: { ...info, name: d.device.name } });
    } finally {
      set.delete(ws);
      if (set.size === 0) this.authing.delete(d.id);
    }
    if (ws.readyState !== WebSocket.OPEN) return null;
    return { id: randomToken(12), ws, deviceId: d.id, ownerId: d.ownerId, grant: d.grant, capabilities, pending: new Map(), alive: true };
  }

  private onAgentFrame(s: Session, f: AgentFrame) {
    if (f.t === "result") {
      if (typeof f.id !== "string") return;
      const p = s.pending.get(f.id);
      if (!p) return; // late answer after timeout or cancel
      if (f.ok === true) p.resolve(f.value);
      else {
        const err: Record<string, unknown> = isPlainObject(f.error) ? f.error : {};
        p.reject(new HostlinkError(cleanText(err.code, 64, "remote_error"), cleanText(err.message, 2000, "Device reported an error"), 502));
      }
      return;
    }
    if (f.t === "bye") {
      if (s.grant.mode === "once") void this.removeDevice(s.deviceId, 1000, "ended").catch((e) => this.emit("error", e));
      else s.ws.close(1000, "bye");
      return;
    }
    s.ws.close(CloseCode.ProtocolError, "unknown frame");
  }

  private failPending(s: Session, err: Error) {
    for (const p of [...s.pending.values()]) p.reject(err);
  }

  private heartbeat() {
    for (const s of this.sessions.values()) {
      if (!s.alive) { s.ws.terminate(); continue; }
      s.alive = false;
      try { s.ws.ping(); } catch { /* closing */ }
    }
  }

  /** Housekeeping: expired pairings, expired grants, abandoned one-time devices. Runs on a timer by default. */
  async sweep(): Promise<void> {
    const now = this.now();
    await this.store.deleteExpiredPairings(now);
    for (const s of [...this.sessions.values()]) {
      if (s.grant.expiresAt !== null && s.grant.expiresAt <= now) await this.removeDevice(s.deviceId, CloseCode.Expired, "expired");
    }
    for (const d of await this.store.listDevices({ mode: "once" })) {
      if (this.isExpired(d, now)) await this.removeDevice(d.id, CloseCode.Expired, "expired");
    }
    this.startLimiter.prune(now);
    this.approveLimiter.prune(now);
  }

  /** Disconnects every device (they will reconnect to the next server) and stops timers. */
  async close(): Promise<void> {
    this.closed = true;
    if (this.sweepTimer) clearInterval(this.sweepTimer);
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    for (const s of [...this.sessions.values()]) {
      this.sessions.delete(s.deviceId);
      this.failPending(s, new HostlinkError("device_offline", "Server shutting down", 503));
      s.ws.close(CloseCode.ServerShutdown, "server shutdown");
    }
    await new Promise<void>((r) => this.wss.close(() => r()));
  }

  private clientIp(req: IncomingMessage): string {
    if (this.trustProxy) {
      const xff = req.headers["x-forwarded-for"];
      const first = (Array.isArray(xff) ? xff[0] : xff)?.split(",")[0]?.trim();
      if (first) return first.slice(0, 64);
    }
    return (req.socket.remoteAddress ?? "unknown").slice(0, 64);
  }
}

export function createHostlinkServer(opts: HostlinkServerOptions): HostlinkServer {
  return new HostlinkServer(opts);
}

// ------------------------------------------------------------------ helpers

function validatePolicy(p: HostlinkPolicy): HostlinkPolicy {
  const bad = (k: string, why: string) => { throw new HostlinkError("invalid_option", `policy.${k} ${why}`); };
  for (const [k, v] of Object.entries(p)) {
    if (k === "allowedScopes" || k === "allowLifetime") continue;
    if (typeof v !== "number" || !Number.isFinite(v) || v <= 0) bad(k, "must be a positive number");
  }
  if (p.allowedScopes !== null && (!Array.isArray(p.allowedScopes) || !p.allowedScopes.every((s) => typeof s === "string" && SCOPE_RE.test(s)))) bad("allowedScopes", "must be null or valid scope names");
  // Agents drop a link that is silent for 75s, so the server must ping well inside that.
  if (p.heartbeatMs < 1000 || p.heartbeatMs > 60_000) bad("heartbeatMs", "must be between 1000 and 60000");
  if (p.callTimeoutMs > p.maxCallTimeoutMs) bad("callTimeoutMs", "must not exceed maxCallTimeoutMs");
  if (p.timedDefaultTtlSeconds > p.timedMaxTtlSeconds) bad("timedDefaultTtlSeconds", "must not exceed timedMaxTtlSeconds");
  if (p.trustedDefaultTtlSeconds > p.trustedMaxTtlSeconds) bad("trustedDefaultTtlSeconds", "must not exceed trustedMaxTtlSeconds");
  return p;
}

function requireOwner(ownerId: unknown): string {
  if (typeof ownerId !== "string" || ownerId.length === 0 || ownerId.length > 256) throw new HostlinkError("invalid_owner", "ownerId is required", 400);
  return ownerId;
}

function parseScopes(v: unknown): string[] {
  if (!Array.isArray(v) || v.length === 0 || v.length > 32) throw new HostlinkError("invalid_scope", "scopes must be a non-empty array");
  for (const s of v) if (typeof s !== "string" || !SCOPE_RE.test(s)) throw new HostlinkError("invalid_scope", `Invalid scope name`);
  return [...new Set(v as string[])];
}

function parseMode(v: unknown): GrantMode {
  if (typeof v !== "string" || !GRANT_MODES.includes(v as GrantMode)) throw new HostlinkError("invalid_mode", "mode must be once, timed or trusted");
  return v as GrantMode;
}

function parseTtl(v: unknown): number {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 60 || v > 100 * 365 * 86400) throw new HostlinkError("invalid_ttl", "ttlSeconds must be a whole number of seconds, at least 60");
  return v;
}

function parseDeviceInfo(v: unknown): DeviceInfo {
  if (!isPlainObject(v)) throw new HostlinkError("invalid_request", "device info required");
  return {
    name: cleanText(v.name, 64, "Unnamed device"),
    platform: cleanText(v.platform, 32, "unknown"),
    arch: cleanText(v.arch, 32, "unknown"),
    agentVersion: cleanText(v.agentVersion, 32, "unknown"),
  };
}

function parseCapabilities(v: unknown): CapabilityDescriptor[] {
  if (!Array.isArray(v) || v.length > 64) throw new Error("capabilities");
  const out: CapabilityDescriptor[] = [];
  for (const c of v) {
    if (!isPlainObject(c) || typeof c.name !== "string" || !SCOPE_RE.test(c.name) || !Array.isArray(c.methods) || c.methods.length > 256) throw new Error("capability");
    for (const m of c.methods) if (typeof m !== "string" || !METHOD_RE.test(m)) throw new Error("method");
    out.push({ name: c.name, methods: [...new Set(c.methods as string[])] });
  }
  return out;
}

function safeSend(ws: WebSocket, frame: ServerFrame) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(frame), () => {});
}

function sendJson(res: ServerResponse, status: number, body: unknown) {
  const data = JSON.stringify(body);
  const headers: Record<string, string | number> = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "content-length": Buffer.byteLength(data) };
  if (status === 413) headers.connection = "close";
  res.writeHead(status, headers);
  res.end(data);
}

function readJson(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let size = 0;
    let failed = false;
    const chunks: Buffer[] = [];
    const onData = (c: Buffer) => {
      size += c.length;
      if (size <= MAX_BODY) { chunks.push(c); return; }
      failed = true;
      chunks.length = 0;
      req.off("data", onData);
      req.resume(); // discard the rest; the 413 goes out with Connection: close
      reject(new HostlinkError("payload_too_large", "Body too large", 413));
    };
    req.on("data", onData);
    req.on("end", () => {
      if (failed) return;
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch { reject(new HostlinkError("invalid_json", "Body is not valid JSON")); }
    });
    req.on("error", (e) => { if (!failed) reject(e); });
  });
}
