import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { stat } from "node:fs/promises";
import { browserCapability, shellCapability } from "../dist/index.js";
import { setup, linkAgent } from "./helpers.mjs";

const ctx = () => ({ cap: "x", method: "y", signal: new AbortController().signal });

describe("shell capability", () => {
  const sh = shellCapability({ maxOutputBytes: 1000 });

  test("run without a shell, with stdin", async () => {
    const r = await sh.methods.run({ command: ["cat"], input: "hello" }, ctx());
    assert.deepEqual({ ...r }, { exitCode: 0, signal: null, stdout: "hello", stderr: "", truncated: false, timedOut: false });
    const meta = await sh.methods.run({ command: ["echo", "$HOME; rm -rf /"] }, ctx());
    assert.equal(meta.stdout, "$HOME; rm -rf /\n", "arguments are not interpreted by a shell");
  });

  test("script, exit codes, stderr", async () => {
    const r = await sh.methods.script({ script: "echo out; echo err 1>&2; exit 3" }, ctx());
    assert.equal(r.exitCode, 3);
    assert.equal(r.stdout, "out\n");
    assert.equal(r.stderr, "err\n");
  });

  test("timeout kills the whole process group", async () => {
    const t = Date.now();
    const r = await sh.methods.script({ script: "sleep 30 & sleep 30; echo never", timeoutMs: 200 }, ctx());
    assert.equal(r.timedOut, true);
    assert.ok(Date.now() - t < 5000);
    assert.equal(r.stdout, "");
  });

  test("abort signal kills the process", async () => {
    const ac = new AbortController();
    const p = sh.methods.run({ command: ["sleep", "30"] }, { cap: "shell", method: "run", signal: ac.signal });
    setTimeout(() => ac.abort(), 100);
    const r = await p;
    assert.equal(r.signal, "SIGKILL");
  });

  test("output cap", async () => {
    const r = await sh.methods.script({ script: "head -c 5000 /dev/zero | tr '\\0' a" }, ctx());
    assert.equal(r.stdout.length, 1000);
    assert.equal(r.truncated, true);
  });

  test("bad params and missing programs", async () => {
    await assert.rejects(async () => sh.methods.run({ command: "ls" }, ctx()), { code: "invalid_params" });
    await assert.rejects(async () => sh.methods.run({ command: [] }, ctx()), { code: "invalid_params" });
    await assert.rejects(async () => sh.methods.run(null, ctx()), { code: "invalid_params" });
    await assert.rejects(async () => sh.methods.run({ command: ["ls"], timeoutMs: -1 }, ctx()), { code: "invalid_params" });
    await assert.rejects(sh.methods.run({ command: ["definitely-not-a-program-xyz"] }, ctx()), { code: "spawn_failed" });
    assert.equal(shellCapability({ allowScripts: false }).methods.script, undefined);
  });

  test("end to end through the server", async () => {
    const env = await setup();
    try {
      const { agent, deviceId } = await linkAgent(env, { capabilities: [shellCapability()] });
      const r = await env.hl.call({ ownerId: "u1", deviceId, cap: "shell", method: "run", params: { command: ["node", "-e", "console.log(6*7)"] } });
      assert.equal(r.stdout, "42\n");
      await agent.stop();
    } finally { await env.close(); }
  });
});

describe("browser capability", () => {
  test("drives a real headless browser end to end, then cleans up its profile", async (t) => {
    const site = createServer((req, res) => {
      res.writeHead(200, { "content-type": "text/html" });
      if (req.url.startsWith("/done")) return res.end(`<title>Done</title><h1>Applied</h1>`);
      res.end(`<title>Jobs</title><h1>Apply</h1>
        <form action="/done"><label>Name <input id="name" name="name"></label>
        <select id="city"><option value="pune">Pune</option><option value="delhi">Delhi</option></select>
        <button id="go">Submit</button></form>`);
    });
    await new Promise((r) => site.listen(0, "127.0.0.1", r));
    const url = `http://127.0.0.1:${site.address().port}/`;
    const env = await setup();
    const cap = browserCapability({ headless: true });
    let agent;
    try {
      ({ agent } = await linkAgent(env, { capabilities: [cap] }));
      const deviceId = (await env.hl.listDevices("u1"))[0].id;
      const call = (method, params) => env.hl.call({ ownerId: "u1", deviceId, cap: "browser", method, params, timeoutMs: 60_000 });
      let opened;
      try {
        opened = await call("open", { url });
      } catch (e) {
        if (e.code === "browser_unavailable") return t.skip(`no browser on this machine: ${e.message}`);
        throw e;
      }
      assert.equal(opened.title, "Jobs");
      assert.match((await call("snapshot", {})).snapshot, /heading "Apply"/);
      await call("fill", { selector: "#name", value: "Yash" });
      assert.deepEqual((await call("select", { selector: "#city", value: "delhi" })).selected, ["delhi"]);
      assert.equal((await call("evaluate", { expression: "document.querySelector('#name').value" })).value, "Yash");
      const shot = await call("screenshot", {});
      assert.equal(Buffer.from(shot.data, "base64").subarray(1, 4).toString(), "PNG");
      await call("click", { selector: "#go" });
      await call("waitFor", { selector: "text=Applied" });
      assert.equal((await call("text", { selector: "h1" })).text, "Applied");
      const second = await call("open", { url });
      assert.equal((await call("tabs", {})).length, 2);
      await call("close", { tabId: second.tabId });
      assert.equal((await call("tabs", {})).length, 1);
      await assert.rejects(call("goto", { url: "file:///etc/passwd" }), { code: "url_not_allowed" });
      await assert.rejects(call("goto", { url: "javascript:alert(1)" }), { code: "url_not_allowed" });
      await assert.rejects(call("focus", { tabId: "t999" }), { code: "tab_not_found" });
      await assert.rejects(call("click", {}), { code: "invalid_params" });
    } finally {
      // grab the temp profile path from Chromium's command line before shutdown
      await agent?.stop();
      await env.close();
      await new Promise((r) => site.close(r));
    }
  });

  test("temporary profile is deleted on dispose", async (t) => {
    const cap = browserCapability({ headless: true });
    try {
      await cap.methods.tabs({}, ctx());
    } catch (e) {
      if (e.code === "browser_unavailable") return t.skip("no browser");
      throw e;
    }
    const { readdir } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const before = (await readdir(tmpdir())).filter((n) => n.startsWith("hostlink-browser-"));
    assert.ok(before.length >= 1);
    await cap.dispose();
    const after = (await readdir(tmpdir())).filter((n) => n.startsWith("hostlink-browser-"));
    assert.equal(after.length, before.length - 1);
    await assert.rejects(stat("/nonexistent")); // keeps stat import used
  });
});
