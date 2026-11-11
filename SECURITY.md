# Security model

hostlink gives a remote program real control of a machine. Read this before you ship it.

## What it protects against

| Threat | Defence |
|---|---|
| Stolen or leaked credentials | There are no bearer tokens. Each device holds an Ed25519 private key that never leaves it, and every connection signs a fresh server nonce. Database leaks reveal only public keys and hashed codes. |
| Replaying a captured handshake | The nonce is per connection, random, and single use. |
| A malicious server relaying a device's signature to another server | The signed message includes the audience (server origin + prefix) that the *agent* was configured with. |
| Guessing a pairing code | 20^8 codes, a 10-minute lifetime, approval only by a signed-in user, and failed attempts limited per user (10 per 10 min by default). Start requests are rate limited per IP. |
| One user reaching another user's device | Every server API takes `ownerId`, and devices of other owners behave as if they do not exist. |
| A compromised or buggy server asking for more than was granted | The agent enforces the grant and its own method table locally, and never dispatches to inherited object properties. |
| Links that outlive their purpose | Every grant has an expiry (lifetime only if you enable it *and* the approver asks). "once" links die when the agent stops or stays offline for 2 minutes. Expiry is enforced on connect, on every call, and by a periodic sweep. The agent also stops itself at expiry. |
| Revocation lag | Revoke closes the live socket at once (including one that is mid-handshake), fails pending calls, and the agent deletes its key. |
| Downgrade to plain text | The agent refuses `http://` to anything but localhost unless you pass `allowInsecure`. Redirects are not followed. |
| Spoofed device names on the approval screen | Names are stripped of control and bidirectional-override characters and truncated. |
| Oversized or malformed input | Request bodies are capped at 16 KiB, WebSocket frames at 32 MiB (configurable), and all fields are validated. Calls in flight are capped per device. |

## What it does NOT protect against, and what you must do

1. **Your approval page is the root of trust.** Put it behind your normal login, protect the approve action against CSRF, and pass the signed-in user's id as `ownerId`. Never approve from an unauthenticated route.
2. **Consent phishing.** The device-code flow can be abused. An attacker runs the agent on *their* machine and tricks a victim into approving the code. The victim's agent would then send its actions, and anything it types (passwords included), to the attacker's machine. Mitigations: show the device name, platform and IP prominently. Tell users to approve only a code they can see on a screen in front of them. Never let your agent type secrets into a device it did not see the user pair moments ago.
3. **A linked device is fully controlled within its scopes.** `shell` is equivalent to the user's account on that machine. `browser` in attach mode (`--cdp`) sees every logged-in site. Offer the narrowest scope that does the job, and prefer `once` on machines you do not own.
4. **The key file.** Timed and trusted links store the private key in `~/.config/hostlink/credentials.json` with mode 0600. Anyone with that user's file access can impersonate the device until it is revoked or expires. `once` links never touch disk.
5. **Proxies.** Only set `trustProxy` when a proxy you control sets `X-Forwarded-For`; otherwise clients can spoof their IP. Terminate TLS in front of the server.
6. **Rate limits are per process.** If you run several server processes, put pairing behind a shared limiter too.
7. **Calls from your agent.** hostlink authenticates the device to the server. It does not decide what your agent is allowed to ask for. Put approval steps in front of sensitive actions (submitting forms, payments, deleting files) in your agent, or run the CLI with `--confirm`.

## Reporting

Please report vulnerabilities privately to the maintainers rather than in a public issue.
