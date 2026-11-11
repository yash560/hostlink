// Minimal reference integration. Run:  HOSTLINK_DEMO_PASSWORD=secret node examples/server.mjs
// Then on any machine:               npx hostlink connect http://localhost:8787
//
// "Sign-in" here is a single shared password so the example stays short. In a real product the
// approval page sits behind YOUR normal login + CSRF protection, and ownerId is the signed-in user's id.
import { createServer } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { createHostlinkServer, FileStore } from "hostlink/server";

const PORT = Number(process.env.PORT ?? 8787);
const PUBLIC_URL = process.env.PUBLIC_URL ?? `http://localhost:${PORT}`;
const PASSWORD = process.env.HOSTLINK_DEMO_PASSWORD;
if (!PASSWORD) throw new Error("Set HOSTLINK_DEMO_PASSWORD");
const OWNER = "demo-user";

const hostlink = createHostlinkServer({
  publicUrl: PUBLIC_URL,
  verificationUri: `${PUBLIC_URL}/link`,
  store: await FileStore.open(process.env.HOSTLINK_DB ?? "./hostlink-devices.json"),
  policy: { allowedScopes: ["browser", "shell"] },
});
hostlink.on("device:online", (d) => console.log("online", d.deviceId));
hostlink.on("device:offline", (d) => console.log("offline", d.deviceId));

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const authed = (pw) => {
  const a = Buffer.from(String(pw ?? "")), b = Buffer.from(PASSWORD);
  return a.length === b.length && timingSafeEqual(a, b);
};
const body = (req) => new Promise((resolve, reject) => {
  let s = "";
  req.on("data", (c) => { s += c; if (s.length > 1e6) req.destroy(); });
  req.on("end", () => resolve(s));
  req.on("error", reject);
});
const json = (res, status, v) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(v)); };
const html = (res, s) => { res.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'" }); res.end(`<!doctype html><meta name=viewport content="width=device-width"><body style="font:16px system-ui;max-width:32rem;margin:2rem auto;padding:0 1rem">${s}`); };

const server = createServer(async (req, res) => {
  try {
    if (await hostlink.handleRequest(req, res)) return;
    const url = new URL(req.url, PUBLIC_URL);

    if (req.method === "GET" && url.pathname === "/link") {
      const code = url.searchParams.get("code") ?? "";
      const p = code ? await hostlink.describePairing(code) : null;
      return html(res, p
        ? `<h1>Link this device?</h1>
           <p><b>${esc(p.device.name)}</b> (${esc(p.device.platform)}/${esc(p.device.arch)}) from ${esc(p.ip)}</p>
           <p>Code <b>${esc(p.userCode)}</b>. Only approve if this is the code on the screen in front of you.</p>
           <p>Wants: ${p.requested.scopes.map(esc).join(", ")}, ${esc(p.requested.mode)}</p>
           <form method=post action=/link>
             <input type=hidden name=code value="${esc(p.userCode)}">
             <label>Password <input type=password name=password required></label>
             <p><button name=decision value=approve>Approve</button> <button name=decision value=deny>Deny</button></p>
           </form>`
        : `<h1>Link a device</h1><form><label>Code <input name=code autofocus></label> <button>Next</button></form>`);
    }
    if (req.method === "POST" && url.pathname === "/link") {
      const f = new URLSearchParams(await body(req));
      if (!authed(f.get("password"))) return html(res, "<p>Wrong password.</p>");
      try {
        if (f.get("decision") === "deny") { await hostlink.deny({ userCode: f.get("code"), ownerId: OWNER }); return html(res, "<p>Denied.</p>"); }
        const r = await hostlink.approve({ userCode: f.get("code"), ownerId: OWNER });
        return html(res, `<p>Linked <b>${esc(r.device.name)}</b>. You can close this page.</p>`);
      } catch (e) { return html(res, `<p>${esc(e.message)}</p>`); }
    }

    // Tiny JSON API for your agent backend: Authorization: Bearer <password>
    if (url.pathname.startsWith("/api/")) {
      if (!authed((req.headers.authorization ?? "").replace(/^Bearer /, ""))) return json(res, 401, { error: "unauthorized" });
      const b = req.method === "POST" ? JSON.parse((await body(req)) || "{}") : {};
      if (url.pathname === "/api/devices") return json(res, 200, await hostlink.listDevices(OWNER));
      if (url.pathname === "/api/call") return json(res, 200, { value: await hostlink.call({ ownerId: OWNER, deviceId: b.deviceId, cap: b.cap, method: b.method, params: b.params, timeoutMs: b.timeoutMs }) });
      if (url.pathname === "/api/revoke") return json(res, 200, { revoked: await hostlink.revoke({ ownerId: OWNER, deviceId: b.deviceId }) });
    }
    json(res, 404, { error: "not_found" });
  } catch (e) {
    json(res, e.status ?? 500, { error: e.code ?? "internal_error", message: e.status ? e.message : "Internal error" });
  }
});
hostlink.attach(server);
server.listen(PORT, () => console.log(`hostlink example on ${PUBLIC_URL}`));
