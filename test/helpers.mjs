import { createServer } from "node:http";
import { WebSocket } from "ws";
import { createHostlinkServer, HostlinkAgent, MemoryCredentialStore, generateDeviceKey, signAuth, PROTOCOL_VERSION } from "../dist/index.js";

export const echoCap = (log = {}) => ({
  name: "echo",
  methods: {
    echo: (p) => p,
    fail: () => { throw Object.assign(new Error("boom happened"), { code: "boom" }); },
    slow: (p, ctx) => new Promise((resolve) => {
      const t = setTimeout(() => resolve("late"), p.ms);
      ctx.signal.addEventListener("abort", () => { clearTimeout(t); log.aborted = true; resolve("aborted"); });
    }),
    circular: () => { const o = {}; o.o = o; return o; },
  },
});

export async function setup({ policy = {}, ...rest } = {}) {
  const clock = { offset: 0 };
  const http = createServer();
  await new Promise((r) => http.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${http.address().port}`;
  const hl = createHostlinkServer({
    publicUrl: base,
    verificationUri: `${base}/link`,
    sweepIntervalMs: 0,
    now: () => Date.now() + clock.offset,
    policy: { pollIntervalSeconds: 0.05, ...policy },
    ...rest,
  });
  http.on("request", async (req, res) => {
    if (await hl.handleRequest(req, res)) return;
    res.writeHead(404).end("not found");
  });
  hl.attach(http);
  const errors = [];
  hl.on("error", (e) => errors.push(e));
  return {
    hl, http, base, clock, errors,
    async close() {
      await hl.close();
      http.closeAllConnections?.();
      await new Promise((r) => http.close(r));
    },
  };
}

/** Starts an agent and approves it as `ownerId` as soon as the code appears. */
export async function linkAgent(env, { approve = {}, ownerId = "u1", ...agentOpts } = {}) {
  const agent = new HostlinkAgent({
    server: env.base,
    mode: "once",
    capabilities: [echoCap()],
    credentials: new MemoryCredentialStore(),
    ...agentOpts,
  });
  const statuses = [];
  agent.on("status", (s) => {
    statuses.push(s);
    if (s.state === "pairing" && approve !== false) env.hl.approve({ userCode: s.userCode, ownerId, ...approve }).catch((e) => statuses.push({ state: "approve-error", e }));
  });
  const res = await agent.start();
  return { agent, statuses, ...res };
}

export async function post(base, action, body, headers = { "content-type": "application/json" }) {
  const r = await fetch(`${base}/hostlink/v1/pair/${action}`, { method: "POST", headers, body: typeof body === "string" ? body : JSON.stringify(body) });
  return { status: r.status, body: await r.json().catch(() => null) };
}

export const startBody = (publicKey, requested = {}) => ({
  v: PROTOCOL_VERSION,
  publicKey,
  device: { name: "raw", platform: "linux", arch: "x64", agentVersion: "test" },
  requested: { scopes: ["echo"], mode: "once", ttlSeconds: null, ...requested },
});

/** Pairs without the agent class, for protocol-level tests. */
export async function rawPair(env, { requested, approve = {}, ownerId = "u1" } = {}) {
  const key = generateDeviceKey();
  const s = await post(env.base, "start", startBody(key.publicKey, requested));
  if (s.status !== 200) throw new Error(JSON.stringify(s.body));
  await env.hl.approve({ userCode: s.body.userCode, ownerId, ...approve });
  const p = await post(env.base, "poll", { deviceCode: s.body.deviceCode });
  if (p.body.status !== "approved") throw new Error(JSON.stringify(p.body));
  return { key, deviceId: p.body.deviceId, grant: p.body.grant, deviceCode: s.body.deviceCode };
}

/** Opens a raw socket and answers the challenge with `sign(nonce)`. Resolves with { ws, first } where first is ready frame or close info. */
export function rawConnect(env, { deviceId, sign, capabilities = [{ name: "echo", methods: ["echo", "slow"] }], send = true }) {
  return new Promise((resolve) => {
    const ws = new WebSocket(`${env.base.replace("http", "ws")}/hostlink/v1/connect`);
    const frames = [];
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve({ ws, frames, ...v }); } };
    ws.on("message", (raw) => {
      const f = JSON.parse(raw.toString());
      frames.push(f);
      if (f.t === "challenge" && send) {
        ws.send(JSON.stringify({ t: "auth", v: PROTOCOL_VERSION, deviceId, sig: sign(f.nonce), capabilities, device: { name: "x", platform: "linux", arch: "x64", agentVersion: "t" } }));
      }
      if (f.t === "ready") finish({ ready: f });
    });
    ws.on("close", (code, reason) => finish({ closed: { code, reason: reason.toString() } }));
    ws.on("error", () => {});
  });
}

export const signer = (key, audience, deviceId) => (nonce) => signAuth(key.privateKey, audience, deviceId, nonce);

export function waitClose(ws) {
  return new Promise((r) => {
    if (ws.readyState === WebSocket.CLOSED) return r({ code: -1 });
    ws.on("close", (code, reason) => r({ code, reason: reason.toString() }));
  });
}

export async function until(fn, ms = 3000) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error("timed out waiting for condition");
    await new Promise((r) => setTimeout(r, 20));
  }
}
