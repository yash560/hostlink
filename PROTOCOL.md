# hostlink protocol, version 1

All JSON. `{prefix}` defaults to `/hostlink`. The **audience** is `scheme://host[:port]{prefix}` of the server URL the agent was configured with (for example `https://app.example.com/hostlink`). The agent never takes the audience from the server.

## 1. Pairing (device authorisation grant, after RFC 8628)

The agent generates an Ed25519 key pair. The private key never leaves the device.

`POST {prefix}/v1/pair/start` (`Content-Type: application/json`)

```json
{ "v": 1,
  "publicKey": "<base64url raw 32 bytes>",
  "device": { "name": "Work laptop", "platform": "darwin", "arch": "arm64", "agentVersion": "0.1.0" },
  "requested": { "scopes": ["browser"], "mode": "once" | "timed" | "trusted", "ttlSeconds": 86400 | null } }
```

The response is `200`:

```json
{ "deviceCode": "<secret, 43 chars>", "userCode": "BCDF-GHJK",
  "verificationUri": "https://app.example.com/link",
  "verificationUriComplete": "https://app.example.com/link?code=BCDF-GHJK",
  "expiresIn": 600, "interval": 3 }
```

The request is rejected up front if it is outside the server policy (unknown scope, TTL too long, and so on).

The user opens the verification URI while signed in to the server's app. The app shows the device name, IP, scopes and mode (`describePairing`), and the user approves or denies. The user code is 8 letters from `BCDFGHJKLMNPQRSTVWXZ`, about 34 bits, valid for 10 minutes, with failed approval attempts limited per user.

`POST {prefix}/v1/pair/poll` `{ "deviceCode": "..." }`, every `interval` seconds:

| Response | Meaning |
|---|---|
| `{"status":"pending"}` | Keep polling |
| `{"status":"slow_down","interval":N}` | Polled too fast; use the new interval |
| `{"status":"denied"}` / `{"status":"expired"}` | Stop |
| `{"status":"approved","deviceId":"dev_...","grant":{"scopes":[...],"mode":"...","expiresAt":<ms>|null}}` | Paired. The device code is now spent. |

Errors are `{"error": "<code>", "message": "..."}` with a 4xx/5xx status.

## 2. Connection

`GET {prefix}/v1/connect` upgraded to WebSocket. Text frames only, one JSON object each.

```
server → {"t":"challenge","v":1,"nonce":"<base64url 32 random bytes>"}
agent  → {"t":"auth","v":1,"deviceId":"dev_...","sig":"<base64url Ed25519 signature>",
          "capabilities":[{"name":"browser","methods":["open","click",...]}],
          "device":{...}}
server → {"t":"ready","sessionId":"...","deviceId":"dev_...","grant":{...}}
```

The signed message is the UTF-8 string:

```
hostlink-auth-v1\n{audience}\n{deviceId}\n{nonce}
```

The nonce is fresh per connection, so a recorded `auth` frame is useless. Binding the audience means a signature made for one server cannot be relayed to another. The agent must send `auth` within 10 s.

### Calls

```
server → {"t":"call","id":"<id>","cap":"browser","method":"open","params":{...}}
agent  → {"t":"result","id":"<id>","ok":true,"value":<json>}
agent  → {"t":"result","id":"<id>","ok":false,"error":{"code":"<snake_case>","message":"..."}}
server → {"t":"cancel","id":"<id>"}           (timeout or abort; the agent aborts the work)
agent  → {"t":"bye"}                           (agent is stopping; for "once" links this ends the grant)
```

Both sides check scope: the server will not send, and the agent will not run, a call whose `cap` is not in the grant or whose method the agent does not offer. The server pings every 20 s. An agent that hears nothing for 75 s reconnects.

### Close codes

| Code | Meaning | Agent behaviour |
|---|---|---|
| 1000 | Normal | Stop |
| 4400 | Protocol error | Stop |
| 4401 | Unauthorized (unknown device or bad signature) | Stop, delete key |
| 4403 | Revoked | Stop, delete key |
| 4408 | Auth timeout | Reconnect |
| 4409 | Replaced by a newer connection of the same device | Stop |
| 4410 | Grant expired | Stop, delete key |
| 4503 | Server shutting down | Reconnect |
| other | Network | Reconnect with jittered exponential backoff (max 30 s) |
