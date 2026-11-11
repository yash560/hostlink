import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, stat, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WebSocketServer, WebSocket as WS } from "ws";
import {
  HostlinkAgent, MemoryCredentialStore, FileCredentialStore, FileStore, shellCapability,
  generateDeviceKey, normalizeUserCode, generateUserCode, CloseCode, PROTOCOL_VERSION, parseDuration,
} from "../dist/index.js";
import { setup, linkAgent, echoCap, post, startBody, rawPair, rawConnect, signer, waitClose, until } from "./helpers.mjs";

const rejects = (p, code) => assert.rejects(p, (e) => { assert.equal(e.code, code, `expected ${code}, got ${e.code}: ${e.message}`); return true; });

describe("pairing and calls", () => {
  test("full flow: pair, approve, call, list, stop", async () => {
    const env = await setup();
    try {
      const { agent, deviceId, grant, statuses } = await linkAgent(env, { name: "Friend laptop" });
      assert.equal(grant.mode, "once");
      assert.deepEqual(grant.scopes, ["echo"]);
      assert.ok(statuses.find((s) => s.state === "pairing").verificationUriComplete.includes("?code="));
      assert.deepEqual(await env.hl.call({ ownerId: "u1", deviceId, cap: "echo", method: "echo", params: { a: [1, "x"] } }), { a: [1, "x"] });
      assert.equal(await env.hl.call({ ownerId: "u1", deviceId, cap: "echo", method: "echo" }), null);
      const [d] = await env.hl.listDevices("u1");
      assert.equal(d.id, deviceId);
      assert.equal(d.online, true);
      assert.equal(d.device.name, "Friend laptop");
      assert.deepEqual(d.capabilities[0].name, "echo");
      await agent.stop();
      // once mode: "bye" removes the device on the server
      await until(async () => (await env.hl.listDevices("u1")).length === 0);
      assert.equal(await agent.done, "stopped");
    } finally { await env.close(); }
  });

  test("remote errors carry the device's code; unserialisable results are reported", async () => {
    const env = await setup();
    try {
      const { agent, deviceId } = await linkAgent(env);
      await assert.rejects(env.hl.call({ ownerId: "u1", deviceId, cap: "echo", method: "fail" }), (e) => e.code === "boom" && e.message === "boom happened" && e.status === 502);
      await rejects(env.hl.call({ ownerId: "u1", deviceId, cap: "echo", method: "circular" }), "unserialisable_result");
      await agent.stop();
    } finally { await env.close(); }
  });

  test("denied pairing rejects start()", async () => {
    const env = await setup();
    try {
      const agent = new HostlinkAgent({ server: env.base, mode: "once", capabilities: [echoCap()] });
      agent.on("status", (s) => { if (s.state === "pairing") env.hl.deny({ userCode: s.userCode, ownerId: "u1" }); });
      await rejects(agent.start(), "pairing_denied");
      assert.match(await agent.done, /pairing failed/);
    } finally { await env.close(); }
  });

  test("approver can narrow scopes; server and device both enforce them", async () => {
    const env = await setup();
    try {
      const { agent, deviceId, grant } = await linkAgent(env, { capabilities: [echoCap(), shellCapability()], approve: { scopes: ["echo"] } });
      assert.deepEqual(grant.scopes, ["echo"]);
      await assert.rejects(env.hl.call({ ownerId: "u1", deviceId, cap: "shell", method: "run", params: { command: ["id"] } }), (e) => e.code === "scope_not_granted" && e.status === 403);
      await rejects(env.hl.call({ ownerId: "u1", deviceId, cap: "echo", method: "nope" }), "method_not_supported");
      await agent.stop();
    } finally { await env.close(); }
  });

  test("another owner cannot see, call or revoke the device", async () => {
    const env = await setup();
    try {
      const { agent, deviceId } = await linkAgent(env);
      await rejects(env.hl.call({ ownerId: "u2", deviceId, cap: "echo", method: "echo" }), "device_not_found");
      assert.equal(await env.hl.revoke({ ownerId: "u2", deviceId }), false);
      assert.deepEqual(await env.hl.listDevices("u2"), []);
      assert.equal(await env.hl.getDevice("u2", deviceId), null);
      await rejects(env.hl.call({ ownerId: "", deviceId, cap: "echo", method: "echo" }), "invalid_owner");
      assert.equal(env.hl.isOnline(deviceId), true);
      await agent.stop();
    } finally { await env.close(); }
  });

  test("revoke disconnects at once and the agent forgets its key", async () => {
    const env = await setup();
    const dir = await mkdtemp(join(tmpdir(), "hl-"));
    try {
      const credentials = new FileCredentialStore(join(dir, "c.json"));
      const { agent, deviceId } = await linkAgent(env, { mode: "trusted", credentials });
      assert.ok(await credentials.load(agent.audience));
      assert.equal(await env.hl.revoke({ ownerId: "u1", deviceId }), true);
      assert.equal(await agent.done, "revoked");
      assert.equal(await credentials.load(agent.audience), null);
      await rejects(env.hl.call({ ownerId: "u1", deviceId, cap: "echo", method: "echo" }), "device_not_found");
    } finally { await env.close(); await rm(dir, { recursive: true, force: true }); }
  });

  test("timeout cancels the call on the device; late answers are ignored", async () => {
    const env = await setup();
    try {
      const log = {};
      const { agent, deviceId } = await linkAgent(env, { capabilities: [echoCap(log)] });
      await rejects(env.hl.call({ ownerId: "u1", deviceId, cap: "echo", method: "slow", params: { ms: 2000 }, timeoutMs: 100 }), "timeout");
      await until(() => log.aborted === true);
      // still healthy afterwards
      assert.equal(await env.hl.call({ ownerId: "u1", deviceId, cap: "echo", method: "echo", params: 7 }), 7);
      const ac = new AbortController();
      const p = env.hl.call({ ownerId: "u1", deviceId, cap: "echo", method: "slow", params: { ms: 2000 }, signal: ac.signal });
      ac.abort();
      await rejects(p, "aborted");
      await agent.stop();
    } finally { await env.close(); }
  });

  test("in-flight limit", async () => {
    const env = await setup({ policy: { maxInFlightPerDevice: 2 } });
    try {
      const { agent, deviceId } = await linkAgent(env);
      const slow = () => env.hl.call({ ownerId: "u1", deviceId, cap: "echo", method: "slow", params: { ms: 300 } });
      const a = slow(), b = slow();
      await rejects(slow(), "device_busy");
      assert.deepEqual(await Promise.all([a, b]), ["late", "late"]);
      await agent.stop();
    } finally { await env.close(); }
  });

  test("pending calls fail when the device drops, and the agent reconnects by itself", async () => {
    const env = await setup();
    try {
      const { agent, deviceId, statuses } = await linkAgent(env, { mode: "timed", ttlSeconds: 3600 });
      const p = env.hl.call({ ownerId: "u1", deviceId, cap: "echo", method: "slow", params: { ms: 5000 } });
      env.hl.sessions.get(deviceId).ws.terminate();
      await rejects(p, "device_offline");
      await until(() => env.hl.isOnline(deviceId), 10_000);
      assert.ok(statuses.some((s) => s.state === "reconnecting"));
      assert.equal(await env.hl.call({ ownerId: "u1", deviceId, cap: "echo", method: "echo", params: "back" }), "back");
      await agent.stop();
      // timed links survive a stop: the device stays registered, offline
      await until(async () => (await env.hl.listDevices("u1"))[0]?.online === false);
      await rejects(env.hl.call({ ownerId: "u1", deviceId, cap: "echo", method: "echo" }), "device_offline");
    } finally { await env.close(); }
  });

  test("trusted device: second run reuses the saved key without pairing; file is 0600", async () => {
    const env = await setup();
    const dir = await mkdtemp(join(tmpdir(), "hl-"));
    try {
      const path = join(dir, "sub", "c.json");
      const first = await linkAgent(env, { mode: "trusted", credentials: new FileCredentialStore(path) });
      assert.ok(first.grant.expiresAt > Date.now() + 89 * 86400_000);
      await first.agent.stop();
      if (process.platform !== "win32") {
        assert.equal((await stat(path)).mode & 0o777, 0o600);
        assert.equal((await stat(join(dir, "sub"))).mode & 0o777, 0o700);
      }
      const second = await linkAgent(env, { mode: "trusted", credentials: new FileCredentialStore(path), approve: false });
      assert.equal(second.deviceId, first.deviceId);
      assert.ok(!second.statuses.some((s) => s.state === "pairing"));
      assert.equal(await env.hl.call({ ownerId: "u1", deviceId: second.deviceId, cap: "echo", method: "echo", params: 1 }), 1);
      await second.agent.stop();
      const saved = JSON.parse(await readFile(path, "utf8"));
      assert.equal(Object.keys(saved.credentials).length, 1);
    } finally { await env.close(); await rm(dir, { recursive: true, force: true }); }
  });

  test("once mode never writes the key to disk", async () => {
    const env = await setup();
    const dir = await mkdtemp(join(tmpdir(), "hl-"));
    try {
      const path = join(dir, "c.json");
      const { agent } = await linkAgent(env, { mode: "once", credentials: new FileCredentialStore(path) });
      await agent.stop();
      await assert.rejects(stat(path), { code: "ENOENT" });
    } finally { await env.close(); await rm(dir, { recursive: true, force: true }); }
  });

  test("timed grant expiry disconnects and removes the device", async () => {
    const env = await setup();
    try {
      const credentials = new MemoryCredentialStore();
      const { agent, deviceId, grant } = await linkAgent(env, { mode: "timed", ttlSeconds: 120, credentials });
      assert.ok(Math.abs(grant.expiresAt - (Date.now() + 120_000)) < 2000);
      env.clock.offset = 121_000;
      await rejects(env.hl.call({ ownerId: "u1", deviceId, cap: "echo", method: "echo" }), "grant_expired");
      assert.equal(await agent.done, "expired");
      assert.equal(await credentials.load(agent.audience), null);
      assert.deepEqual(await env.hl.listDevices("u1"), []);
    } finally { await env.close(); }
  });

  test("sweep expires live sessions too", async () => {
    const env = await setup();
    try {
      const { agent } = await linkAgent(env, { mode: "timed", ttlSeconds: 60 });
      env.clock.offset = 61_000;
      await env.hl.sweep();
      assert.equal(await agent.done, "expired");
    } finally { await env.close(); }
  });

  test("server shutdown: agent keeps retrying (not terminal)", async () => {
    const env = await setup();
    const { agent, statuses } = await linkAgent(env, { mode: "timed", ttlSeconds: 3600 });
    await env.hl.close();
    await until(() => statuses.some((s) => s.state === "reconnecting" && s.code === CloseCode.ServerShutdown));
    await agent.stop();
    await env.close().catch(() => {});
  });
});

describe("authentication", () => {
  test("wrong key, unknown device, garbage signature: all 4401", async () => {
    const env = await setup();
    try {
      const { deviceId } = await rawPair(env, { requested: { mode: "timed" } });
      const other = generateDeviceKey();
      const aud = env.hl.audience;
      assert.equal((await rawConnect(env, { deviceId, sign: signer(other, aud, deviceId) })).closed.code, CloseCode.Unauthorized);
      assert.equal((await rawConnect(env, { deviceId: "dev_nope", sign: signer(other, aud, "dev_nope") })).closed.code, CloseCode.Unauthorized);
      assert.equal((await rawConnect(env, { deviceId, sign: () => "AAAA" })).closed.code, CloseCode.Unauthorized);
      assert.equal((await rawConnect(env, { deviceId, sign: () => 5 })).closed.code, CloseCode.Unauthorized);
    } finally { await env.close(); }
  });

  test("a signature made for another audience is rejected", async () => {
    const env = await setup();
    try {
      const { key, deviceId } = await rawPair(env, { requested: { mode: "timed" } });
      const r = await rawConnect(env, { deviceId, sign: signer(key, "https://evil.example/hostlink", deviceId) });
      assert.equal(r.closed.code, CloseCode.Unauthorized);
      const ok = await rawConnect(env, { deviceId, sign: signer(key, env.hl.audience, deviceId) });
      assert.ok(ok.ready);
      ok.ws.close();
    } finally { await env.close(); }
  });

  test("agent configured with a different host name fails closed (audience mismatch)", async () => {
    const env = await setup();
    try {
      const agent = new HostlinkAgent({ server: env.base.replace("127.0.0.1", "localhost"), mode: "once", capabilities: [echoCap()] });
      agent.on("status", (s) => { if (s.state === "pairing") env.hl.approve({ userCode: s.userCode, ownerId: "u1" }); });
      await rejects(agent.start(), "ended");
      assert.equal(await agent.done, "unauthorized");
    } finally { await env.close(); }
  });

  test("each connection gets a fresh nonce, so a captured auth frame cannot be replayed", async () => {
    const env = await setup();
    try {
      const { key, deviceId } = await rawPair(env, { requested: { mode: "timed" } });
      let captured;
      const first = await rawConnect(env, { deviceId, sign: (n) => (captured = signer(key, env.hl.audience, deviceId)(n)) });
      assert.ok(first.ready);
      first.ws.close();
      const replay = await rawConnect(env, { deviceId, sign: () => captured });
      assert.equal(replay.closed.code, CloseCode.Unauthorized);
      assert.notEqual(first.frames[0].nonce, replay.frames[0].nonce);
    } finally { await env.close(); }
  });

  test("auth timeout, non-auth first frame, binary frame", async () => {
    const env = await setup({ policy: { authTimeoutMs: 150 } });
    try {
      assert.equal((await rawConnect(env, { deviceId: "x", sign: () => "", send: false })).closed.code, CloseCode.AuthTimeout);
      const r = await new Promise((resolve) => {
        const ws = new WS(`${env.base.replace("http", "ws")}/hostlink/v1/connect`);
        ws.on("message", () => ws.send(JSON.stringify({ t: "result", id: "1", ok: true, value: 1 })));
        ws.on("close", (code) => resolve(code));
      });
      assert.equal(r, CloseCode.ProtocolError);
      const b = await new Promise((resolve) => {
        const ws = new WS(`${env.base.replace("http", "ws")}/hostlink/v1/connect`);
        ws.on("message", () => ws.send(Buffer.from([1, 2, 3])));
        ws.on("close", (code) => resolve(code));
      });
      assert.equal(b, CloseCode.ProtocolError);
    } finally { await env.close(); }
  });

  test("a newer connection replaces the older one", async () => {
    const env = await setup();
    try {
      const { key, deviceId } = await rawPair(env, { requested: { mode: "timed" } });
      const sign = signer(key, env.hl.audience, deviceId);
      const a = await rawConnect(env, { deviceId, sign });
      const closeA = waitClose(a.ws);
      const b = await rawConnect(env, { deviceId, sign });
      assert.ok(b.ready);
      assert.equal((await closeA).code, CloseCode.Replaced);
      assert.equal(env.hl.isOnline(deviceId), true);
      b.ws.close();
      await until(() => !env.hl.isOnline(deviceId));
    } finally { await env.close(); }
  });

  test("once device that drops and stays away past the grace is removed", async () => {
    const env = await setup({ policy: { onceDisconnectGraceSeconds: 60 } });
    try {
      const { key, deviceId } = await rawPair(env, { requested: { mode: "once" } });
      const sign = signer(key, env.hl.audience, deviceId);
      const a = await rawConnect(env, { deviceId, sign });
      a.ws.terminate();
      await until(() => !env.hl.isOnline(deviceId));
      env.clock.offset = 30_000;
      await env.hl.sweep();
      assert.equal((await env.hl.listDevices("u1")).length, 1, "still inside grace");
      const back = await rawConnect(env, { deviceId, sign });
      assert.ok(back.ready, "reconnect inside grace works");
      back.ws.terminate();
      await until(() => !env.hl.isOnline(deviceId));
      env.clock.offset = 100_000;
      await env.hl.sweep();
      assert.deepEqual(await env.hl.listDevices("u1"), []);
      assert.equal((await rawConnect(env, { deviceId, sign })).closed.code, CloseCode.Unauthorized);
    } finally { await env.close(); }
  });

  test("device enforces its own grant and method table even if the server misbehaves", async () => {
    const wss = new WebSocketServer({ port: 0, host: "127.0.0.1" });
    await new Promise((r) => wss.on("listening", r));
    const base = `http://127.0.0.1:${wss.address().port}`;
    const results = [];
    let resolveAll;
    const all = new Promise((r) => (resolveAll = r));
    wss.on("connection", (ws) => {
      ws.send(JSON.stringify({ t: "challenge", v: PROTOCOL_VERSION, nonce: "n".repeat(43) }));
      ws.on("message", (raw) => {
        const f = JSON.parse(raw.toString());
        if (f.t === "auth") {
          ws.send(JSON.stringify({ t: "ready", sessionId: "s", deviceId: f.deviceId, grant: { scopes: ["echo"], mode: "timed", expiresAt: Date.now() + 60_000 } }));
          for (const [i, cap, method] of [[1, "shell", "run"], [2, "echo", "constructor"], [3, "echo", "__proto__"], [4, "echo", "hasOwnProperty"], [5, "echo", "echo"]]) {
            ws.send(JSON.stringify({ t: "call", id: String(i), cap, method, params: { command: ["touch", "/tmp/hostlink-should-not-exist"] } }));
          }
        }
        if (f.t === "result") { results.push(f); if (results.length === 5) resolveAll(); }
      });
    });
    const creds = new MemoryCredentialStore();
    const key = generateDeviceKey();
    const { exportPrivateKey, makeAudience } = await import("../dist/index.js");
    const aud = makeAudience(base, "/hostlink");
    await creds.save({ v: 1, audience: aud, deviceId: "dev_x", privateKey: exportPrivateKey(key.privateKey), grant: { scopes: ["echo", "shell"], mode: "timed", expiresAt: Date.now() + 60_000 }, name: "x", savedAt: 0 });
    const agent = new HostlinkAgent({ server: base, mode: "timed", capabilities: [echoCap(), shellCapability()], credentials: creds });
    await agent.start();
    await all;
    const byId = Object.fromEntries(results.map((r) => [r.id, r]));
    assert.equal(byId[1].error.code, "scope_not_granted");
    for (const i of ["2", "3", "4"]) assert.equal(byId[i].error.code, "method_not_supported", `call ${i}`);
    assert.equal(byId[5].ok, true);
    await assert.rejects(stat("/tmp/hostlink-should-not-exist"), { code: "ENOENT" });
    await agent.stop();
    await new Promise((r) => wss.close(r));
  });
});

describe("pairing endpoint hardening", () => {
  test("validation errors", async () => {
    const env = await setup();
    try {
      const key = generateDeviceKey();
      assert.equal((await post(env.base, "start", startBody(key.publicKey), { "content-type": "text/plain" })).status, 415);
      assert.equal((await fetch(`${env.base}/hostlink/v1/pair/start`)).status, 405);
      assert.equal((await post(env.base, "start", "{nope")).body.error, "invalid_json");
      assert.equal((await post(env.base, "start", "x".repeat(20_000))).status, 413);
      assert.equal((await post(env.base, "start", startBody("abc"))).body.error, "invalid_public_key");
      assert.equal((await post(env.base, "start", { ...startBody(key.publicKey), v: 99 })).body.error, "unsupported_version");
      assert.equal((await post(env.base, "start", startBody(key.publicKey, { scopes: ["Bad Scope"] }))).body.error, "invalid_scope");
      assert.equal((await post(env.base, "start", startBody(key.publicKey, { scopes: [] }))).body.error, "invalid_scope");
      assert.equal((await post(env.base, "start", startBody(key.publicKey, { mode: "forever" }))).body.error, "invalid_mode");
      assert.equal((await post(env.base, "start", startBody(key.publicKey, { mode: "timed", ttlSeconds: 1.5 }))).body.error, "invalid_ttl");
      assert.equal((await post(env.base, "start", startBody(key.publicKey, { mode: "timed", ttlSeconds: 365 * 86400 }))).body.error, "invalid_ttl");
      assert.equal((await post(env.base, "poll", { deviceCode: "made-up" })).body.status, "expired");
      assert.equal((await post(env.base, "poll", {})).body.error, "invalid_request");
      assert.equal((await fetch(`${env.base}/hostlink/v1/pair/other`, { method: "POST" })).status, 404);
      assert.equal(env.errors.length, 0);
    } finally { await env.close(); }
  });

  test("server allow-list of scopes", async () => {
    const env = await setup({ policy: { allowedScopes: ["browser"] } });
    try {
      const key = generateDeviceKey();
      const r = await post(env.base, "start", startBody(key.publicKey, { scopes: ["shell"] }));
      assert.equal(r.body.error, "invalid_scope");
    } finally { await env.close(); }
  });

  test("device names are cleaned of control and bidi characters", async () => {
    const env = await setup();
    try {
      const key = generateDeviceKey();
      const body = startBody(key.publicKey);
      body.device.name = "Yash‮\u0007 laptop\n" + "x".repeat(200);
      const s = await post(env.base, "start", body);
      const d = await env.hl.describePairing(s.body.userCode);
      assert.equal(d.device.name.length, 64);
      assert.ok(d.device.name.startsWith("Yash laptop"));
    } finally { await env.close(); }
  });

  test("pair/start is rate limited per IP", async () => {
    const env = await setup({ policy: { pairStartsPerIpPerMinute: 2 } });
    try {
      const key = generateDeviceKey();
      assert.equal((await post(env.base, "start", startBody(key.publicKey))).status, 200);
      assert.equal((await post(env.base, "start", startBody(key.publicKey))).status, 200);
      assert.equal((await post(env.base, "start", startBody(key.publicKey))).status, 429);
    } finally { await env.close(); }
  });

  test("polling too fast gets slow_down with a longer interval", async () => {
    const env = await setup({ policy: { pollIntervalSeconds: 5 } });
    try {
      const key = generateDeviceKey();
      const s = await post(env.base, "start", startBody(key.publicKey));
      assert.equal(s.body.interval, 5);
      assert.equal((await post(env.base, "poll", { deviceCode: s.body.deviceCode })).body.status, "pending");
      const r = await post(env.base, "poll", { deviceCode: s.body.deviceCode });
      assert.deepEqual(r.body, { status: "slow_down", interval: 10 });
    } finally { await env.close(); }
  });

  test("codes expire; device code is single use", async () => {
    const env = await setup({ policy: { pairingTtlSeconds: 60 } });
    try {
      const key = generateDeviceKey();
      const s = await post(env.base, "start", startBody(key.publicKey));
      env.clock.offset = 61_000;
      assert.equal(await env.hl.describePairing(s.body.userCode), null);
      await rejects(env.hl.approve({ userCode: s.body.userCode, ownerId: "u1" }), "invalid_code");
      assert.equal((await post(env.base, "poll", { deviceCode: s.body.deviceCode })).body.status, "expired");
      env.clock.offset = 0;
      const p = await rawPair(env);
      assert.equal((await post(env.base, "poll", { deviceCode: p.deviceCode })).body.status, "expired");
    } finally { await env.close(); }
  });

  test("approve rules: subset scopes, TTL caps, lifetime, single use, brute-force limit", async () => {
    const env = await setup({ policy: { approveFailuresPerOwnerPer10Min: 3 } });
    try {
      const key = generateDeviceKey();
      const s = await post(env.base, "start", startBody(key.publicKey, { scopes: ["echo"], mode: "trusted" }));
      const code = s.body.userCode;
      await rejects(env.hl.approve({ userCode: code, ownerId: "u1", scopes: ["shell"] }), "invalid_scope");
      await rejects(env.hl.approve({ userCode: code, ownerId: "u1", ttlSeconds: 91 * 86400 }), "invalid_ttl");
      await rejects(env.hl.approve({ userCode: code, ownerId: "u1", ttlSeconds: null }), "invalid_ttl");
      await rejects(env.hl.approve({ userCode: code, ownerId: "u1", mode: "once", ttlSeconds: 13 * 3600 }), "invalid_ttl");
      // lower-case with spaces still matches
      const ok = await env.hl.approve({ userCode: code.toLowerCase().replace("-", " "), ownerId: "u1", mode: "timed", ttlSeconds: 3600 });
      assert.equal(ok.grant.mode, "timed");
      await rejects(env.hl.approve({ userCode: code, ownerId: "u1" }), "invalid_code");
      await rejects(env.hl.approve({ userCode: "BCDF-GHJK", ownerId: "u9" }), "invalid_code");
      await rejects(env.hl.approve({ userCode: "BCDF-GHJK", ownerId: "u9" }), "invalid_code");
      await rejects(env.hl.approve({ userCode: "BCDF-GHJK", ownerId: "u9" }), "invalid_code");
      await rejects(env.hl.approve({ userCode: "BCDF-GHJK", ownerId: "u9" }), "rate_limited");
      // a different user is unaffected
      await rejects(env.hl.approve({ userCode: "BCDF-GHJK", ownerId: "u8" }), "invalid_code");
    } finally { await env.close(); }
  });

  test("lifetime grants only when the policy allows and the approver asks", async () => {
    const env = await setup({ policy: { allowLifetime: true } });
    try {
      const a = await rawPair(env, { requested: { mode: "trusted" } });
      assert.ok(a.grant.expiresAt > Date.now(), "no TTL requested = default, not lifetime");
      const b = await rawPair(env, { requested: { mode: "trusted" }, approve: { ttlSeconds: null } });
      assert.equal(b.grant.expiresAt, null);
    } finally { await env.close(); }
  });

  test("concurrent approvals: exactly one wins", async () => {
    const env = await setup();
    try {
      const key = generateDeviceKey();
      const s = await post(env.base, "start", startBody(key.publicKey));
      const results = await Promise.allSettled([1, 2, 3].map(() => env.hl.approve({ userCode: s.body.userCode, ownerId: "u1" })));
      assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
    } finally { await env.close(); }
  });
});

describe("units", () => {
  test("user codes", () => {
    for (let i = 0; i < 500; i++) {
      const c = generateUserCode();
      assert.match(c, /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
      assert.equal(normalizeUserCode(c.toLowerCase()), c);
    }
    assert.equal(normalizeUserCode("ABCD-EFGH"), null); // vowels are not in the alphabet
    assert.equal(normalizeUserCode("BCD"), null);
  });

  test("durations", () => {
    assert.equal(parseDuration("90d"), 90 * 86400);
    assert.equal(parseDuration("2h"), 7200);
    assert.throws(() => parseDuration("forever"));
    assert.throws(() => parseDuration("0d"));
  });

  test("agent refuses plain http to remote hosts and bad capabilities", () => {
    assert.throws(() => new HostlinkAgent({ server: "http://example.com", mode: "once", capabilities: [echoCap()] }), (e) => e.code === "insecure_server");
    new HostlinkAgent({ server: "http://example.com", mode: "once", capabilities: [echoCap()], allowInsecure: true });
    assert.throws(() => new HostlinkAgent({ server: "https://x.dev", mode: "once", capabilities: [] }), (e) => e.code === "invalid_option");
    assert.throws(() => new HostlinkAgent({ server: "https://x.dev", mode: "once", capabilities: [echoCap(), echoCap()] }), (e) => e.code === "invalid_option");
    assert.throws(() => new HostlinkAgent({ server: "https://x.dev", mode: "once", capabilities: [{ name: "Bad", methods: {} }] }), (e) => e.code === "invalid_option");
  });

  test("FileStore keeps devices across restarts", async () => {
    const dir = await mkdtemp(join(tmpdir(), "hl-"));
    try {
      const path = join(dir, "devices.json");
      const env = await setup({ store: await FileStore.open(path) });
      const { deviceId } = await rawPair(env, { requested: { mode: "trusted" } });
      await env.close();
      const reopened = await FileStore.open(path);
      assert.equal((await reopened.getDevice(deviceId)).ownerId, "u1");
      assert.equal((await stat(path)).mode & 0o777, 0o600);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
});

describe("review fixes", () => {
  test("a revoke that lands while the device is signing in still wins", async () => {
    const { MemoryStore } = await import("../dist/index.js");
    class SlowStore extends MemoryStore {
      gate = null;
      async updateDevice(id, patch) { if (this.gate) await this.gate; return super.updateDevice(id, patch); }
    }
    const store = new SlowStore();
    const env = await setup({ store });
    try {
      const { key, deviceId } = await rawPair(env, { requested: { mode: "timed" } });
      let open;
      store.gate = new Promise((r) => (open = r));
      const conn = rawConnect(env, { deviceId, sign: signer(key, env.hl.audience, deviceId) });
      await until(() => env.hl.authing.has(deviceId));
      assert.equal(await env.hl.revoke({ ownerId: "u1", deviceId }), true);
      open();
      const r = await conn;
      assert.equal(r.closed?.code, CloseCode.Revoked);
      assert.equal(env.hl.isOnline(deviceId), false);
    } finally { await env.close(); }
  });

  test("policy is validated", async () => {
    const { createHostlinkServer } = await import("../dist/index.js");
    const mk = (policy) => () => createHostlinkServer({ publicUrl: "https://x.dev", verificationUri: "https://x.dev/link", sweepIntervalMs: 0, policy });
    assert.throws(mk({ heartbeatMs: 0 }), /heartbeatMs/);
    assert.throws(mk({ heartbeatMs: 120_000 }), /heartbeatMs/);
    assert.throws(mk({ maxInFlightPerDevice: -1 }), /maxInFlightPerDevice/);
    assert.throws(mk({ allowedScopes: ["Bad Scope"] }), /allowedScopes/);
    assert.throws(mk({ trustedDefaultTtlSeconds: 200 * 86400 }), /trustedDefaultTtlSeconds/);
    assert.throws(() => createHostlinkServer({ publicUrl: "ftp://x", verificationUri: "https://x.dev/link" }), /publicUrl/);
    const ok = mk({ allowedScopes: ["browser"] })();
    await ok.close();
  });

  test("start() twice is refused", async () => {
    const env = await setup();
    try {
      const { agent } = await linkAgent(env);
      await rejects(agent.start(), "already_started");
      await agent.stop();
    } finally { await env.close(); }
  });

  test("two polls racing after approval get the same device", async () => {
    const env = await setup();
    try {
      const key = generateDeviceKey();
      const s = await post(env.base, "start", startBody(key.publicKey));
      await env.hl.approve({ userCode: s.body.userCode, ownerId: "u1" });
      const [a, b] = await Promise.all([post(env.base, "poll", { deviceCode: s.body.deviceCode }), post(env.base, "poll", { deviceCode: s.body.deviceCode })]);
      const ids = [a, b].filter((r) => r.body.status === "approved").map((r) => r.body.deviceId);
      assert.ok(ids.length >= 1);
      assert.equal(new Set(ids).size, 1);
      assert.equal((await env.hl.listDevices("u1")).length, 1);
    } finally { await env.close(); }
  });
});
