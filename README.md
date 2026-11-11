# hostlink

Let a cloud agent use a real machine: its browser, its shell, or any tool you add. Safely, for as long as you decide.

```
 your laptop                                   your cloud app
┌──────────────────────┐   outbound WSS only  ┌──────────────────────────┐
│ npx hostlink connect │ ───────────────────▶ │ hostlink/server          │
│  browser · shell · … │ ◀─── calls/results ─ │  pair · approve · call() │
└──────────────────────┘                      └──────────────────────────┘
```

* **No ports opened, nothing to configure.** The machine dials out over HTTPS/WebSocket, so it works behind NAT, hotel Wi-Fi and corporate firewalls.
* **Device-code pairing.** The machine shows a short code. You approve it on your phone where you are already signed in. Your password is never typed on the machine.
* **Key-based device identity.** Each machine makes an Ed25519 key that never leaves it. Every connection proves possession of that key with a fresh challenge. There are no bearer tokens to steal.
* **Scoped and time-limited.** You approve exactly which capabilities (`browser`, `shell`, your own) and for how long: until the terminal closes, a few hours, or a trusted device for up to 90 days.
* **Revocable instantly.** Revoking closes the live connection and the machine deletes its key.

## Quick start

Server (any Node HTTP server, Express, Fastify...):

```js
import { createServer } from "node:http";
import { createHostlinkServer, FileStore } from "hostlink/server";

const hostlink = createHostlinkServer({
  publicUrl: "https://app.example.com",
  verificationUri: "https://app.example.com/link",      // a page in YOUR app
  store: await FileStore.open("./devices.json"),         // or implement HostlinkStore on your DB
});

const server = createServer(async (req, res) => {
  if (await hostlink.handleRequest(req, res)) return;    // pairing endpoints
  // ... your app
});
hostlink.attach(server);                                 // WebSocket endpoint
server.listen(3000);
```

On your `/link` page, behind your own login:

```js
const info = await hostlink.describePairing(code);       // show name, IP, scopes, mode
await hostlink.approve({ userCode: code, ownerId: user.id /*, scopes, mode, ttlSeconds */ });
```

Then, from your agent:

```js
const devices = await hostlink.listDevices(user.id);
await hostlink.call({ ownerId: user.id, deviceId, cap: "browser", method: "open", params: { url: "https://example.com" } });
const { snapshot } = await hostlink.call({ ownerId: user.id, deviceId, cap: "browser", method: "snapshot" });
await hostlink.revoke({ ownerId: user.id, deviceId });
```

On the machine:

```sh
npx hostlink connect https://app.example.com                 # one-off: ends on Ctrl+C, nothing saved
npx hostlink connect https://app.example.com --for 8h        # timed
npx hostlink connect https://app.example.com --trusted 90d   # your own machine, survives restarts
npx hostlink connect https://app.example.com --allow browser,shell --confirm
```

A complete runnable integration with an approval page is in [`examples/server.mjs`](examples/server.mjs).

## Link types

| Mode | Lasts | Saved on the machine | Use it for |
|---|---|---|---|
| `once` | Until the agent stops (default cap 12 h). Removed if the machine stays offline for 2 min. | No, the key lives in memory only | A friend's or a shared computer |
| `timed` | `--for 30m` up to 30 days (default 24 h) | Yes (0600 file) | A machine you will use today or this week |
| `trusted` | Up to 90 days (default). A lifetime grant needs `policy.allowLifetime` **and** the approver asking for `ttlSeconds: null` | Yes (0600 file) | Your own computers |

The approver can always narrow what the device asked for: fewer scopes, a shorter time, or a different mode.

## Capabilities

### `browser` (needs `playwright-core`, installed automatically as an optional dependency)

By default it launches Chrome (then Edge, then Playwright's Chromium) with a **fresh temporary profile that is deleted on exit**, in a visible window so the person can log in themselves. With `--cdp http://127.0.0.1:9222` it attaches to a Chrome you started with `--remote-debugging-port=9222`, including your existing tabs and logins.

Methods: `tabs`, `open {url?}`, `goto {url, tabId?}`, `back`, `forward`, `reload`, `focus {tabId}`, `close {tabId?}`, `click {selector | x,y}`, `fill {selector, value}`, `type {text}`, `press {key}`, `select {selector, value|values}`, `scroll {dx?, dy?}`, `waitFor {selector, state?}`, `text {selector?}`, `html {selector?}`, `snapshot {selector?}` (accessibility tree, the cheapest way for a model to read a page), `screenshot {fullPage?, selector?}`, `evaluate {expression}`. Only `http(s)` and `about:blank` URLs are allowed unless `allowNonWebUrls` is set.

### `shell`

`run {command: string[], cwd?, timeoutMs?, input?}` runs a program without a shell. `script {script}` runs through `/bin/sh -c` (or `cmd.exe`). Output is capped, timeouts kill the whole process group. Off unless `--allow shell`.

### Your own

```js
import { HostlinkAgent } from "hostlink/agent";

const agent = new HostlinkAgent({
  server: "https://app.example.com",
  mode: "trusted",
  capabilities: [{
    name: "files",
    methods: {
      list: async ({ dir }, { signal }) => (await fs.readdir(dir)),
    },
  }],
});
agent.on("status", (s) => console.log(s));
await agent.start();
```

A capability name is the scope the user approves. The device refuses any call outside its granted scopes or its own method table, even if the server asks.

## Server API

| | |
|---|---|
| `handleRequest(req, res)` | Serves `POST {prefix}/v1/pair/start` and `/poll`. Resolves `false` for other URLs. |
| `handleUpgrade(req, socket, head)` / `attach(server)` | WebSocket at `{prefix}/v1/connect` |
| `describePairing(code)` | Details for the approval screen, or `null` |
| `approve({userCode, ownerId, scopes?, mode?, ttlSeconds?})` / `deny(...)` | Call only from an authenticated route |
| `listDevices(ownerId)`, `getDevice(ownerId, id)`, `isOnline(id)` | |
| `call({ownerId, deviceId, cap, method, params, timeoutMs?, signal?})` | Resolves with the device's result |
| `revoke({ownerId, deviceId})` | Deletes and disconnects |
| events | `device:paired`, `device:online`, `device:offline`, `device:revoked`, `error` |

Every call that touches a device requires the `ownerId`, and devices are invisible to other owners.

Errors are `HostlinkError` with a stable `code` and an HTTP-ish `status`, e.g. `device_offline` (409), `scope_not_granted` (403), `timeout` (504), `grant_expired` (410), `device_busy` (429).

### Storage

`MemoryStore` (tests), `FileStore` (single process), or implement `HostlinkStore` against your database. `updatePairingIf` must be an atomic compare-and-set (for MongoDB: `findOneAndUpdate({ _id, status }, ...)`). Device codes and user codes are only ever stored as SHA-256 hashes.

### Policy

All limits are configurable (`policy` option); see `DEFAULT_POLICY`. The important ones: `allowedScopes`, `trustedMaxTtlSeconds` (90 days), `allowLifetime` (off), `onceDisconnectGraceSeconds` (120), `maxInFlightPerDevice` (16), `pairStartsPerIpPerMinute` (10), `approveFailuresPerOwnerPer10Min` (10).

Behind a reverse proxy, set `trustProxy: true` so rate limits and the IP shown on the approval screen use `X-Forwarded-For`, and make sure the proxy forwards WebSocket upgrades.

## Security

Read [SECURITY.md](SECURITY.md) before you put this in front of users. The wire protocol is in [PROTOCOL.md](PROTOCOL.md).

## Development

```sh
npm install
npx playwright-core install chromium-headless-shell   # for the browser tests
npm test
```

MIT licence.
