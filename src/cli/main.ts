#!/usr/bin/env node
import { createInterface } from "node:readline/promises";
import { HostlinkAgent, FileCredentialStore, type AgentStatus, type CallRequest, type Capability } from "../agent/index.js";
import { browserCapability } from "../capabilities/browser.js";
import { shellCapability } from "../capabilities/shell.js";
import { HostlinkError, makeAudience, parseDuration, type GrantMode } from "../protocol.js";
import { VERSION } from "../version.js";

const HELP = `hostlink ${VERSION}: link this machine to a cloud agent

Usage:
  hostlink connect <server-url> [options]
  hostlink list                       Show saved links on this machine
  hostlink forget <server-url>        Delete the saved link for a server

How long the link lasts (pick one):
  --once                 Until you press Ctrl+C (default). Nothing is saved on this machine.
  --for <duration>       Timed link, e.g. --for 2h or --for 7d. Survives restarts.
  --trusted [duration]   Trusted device, default 90d. Survives restarts.

What the agent may use:
  --allow <list>         Comma list: browser, shell (default: browser)
  --cdp <url>            Use a Chrome you started with --remote-debugging-port, e.g. http://127.0.0.1:9222
  --headless             Run the browser without a window
  --browser <channel>    chrome, msedge or chromium (default: first one found)
  --profile <dir>        Keep the browser profile in <dir> (default: temporary, deleted on exit)

Other:
  --name <name>          Name shown on the approval screen (default: hostname)
  --prefix <path>        Server path prefix (default: /hostlink)
  --confirm              Ask here before every action
  --insecure             Allow plain http to a non-local server (testing only)
`;

interface Args { _: string[]; flags: Map<string, string | true> }

const VALUE_FLAGS = new Set(["for", "allow", "cdp", "browser", "profile", "name", "prefix"]);

function parseArgs(argv: string[]): Args {
  const out: Args = { _: [], flags: new Map() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (!a.startsWith("--")) { out._.push(a); continue; }
    const [k, inline] = a.slice(2).split("=", 2) as [string, string | undefined];
    if (inline !== undefined) { out.flags.set(k, inline); continue; }
    if (VALUE_FLAGS.has(k)) {
      const v = argv[++i];
      if (v === undefined) throw new HostlinkError("usage", `--${k} needs a value`);
      out.flags.set(k, v);
    } else if (k === "trusted" && argv[i + 1] && /^\d+[smhd]$/i.test(argv[i + 1]!)) {
      out.flags.set(k, argv[++i]!);
    } else out.flags.set(k, true);
  }
  return out;
}

function fmtExpiry(expiresAt: number | null): string {
  if (expiresAt === null) return "never expires";
  const ms = expiresAt - Date.now();
  const h = ms / 3_600_000;
  return `expires ${new Date(expiresAt).toLocaleString()} (${h >= 48 ? `${Math.round(h / 24)} days` : h >= 1 ? `${Math.round(h)} hours` : `${Math.max(1, Math.round(ms / 60_000))} min`})`;
}

async function connect(a: Args) {
  const server = a._[1];
  if (!server) throw new HostlinkError("usage", "hostlink connect <server-url>");
  const f = a.flags;
  let mode: GrantMode = "once";
  let ttlSeconds: number | null = null;
  const picked = ["once", "for", "trusted"].filter((k) => f.has(k));
  if (picked.length > 1) throw new HostlinkError("usage", "Use only one of --once, --for, --trusted");
  if (f.has("for")) { mode = "timed"; ttlSeconds = parseDuration(String(f.get("for"))); }
  if (f.has("trusted")) { mode = "trusted"; const v = f.get("trusted"); ttlSeconds = typeof v === "string" ? parseDuration(v) : null; }

  const allow = String(f.get("allow") ?? "browser").split(",").map((s) => s.trim()).filter(Boolean);
  const caps: Capability[] = [];
  for (const c of new Set(allow)) {
    if (c === "browser") {
      caps.push(browserCapability({
        cdpUrl: f.get("cdp") as string | undefined,
        headless: f.has("headless"),
        channel: f.get("browser") as string | undefined,
        userDataDir: f.get("profile") as string | undefined,
      }));
    } else if (c === "shell") caps.push(shellCapability());
    else throw new HostlinkError("usage", `Unknown capability "${c}" (browser, shell)`);
  }

  let confirm: ((c: CallRequest) => Promise<boolean>) | undefined;
  if (f.has("confirm")) {
    if (!process.stdin.isTTY) throw new HostlinkError("usage", "--confirm needs an interactive terminal");
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    // readline swallows Ctrl+C; hand it to the normal shutdown path
    rl.on("SIGINT", () => process.emit("SIGINT"));
    let queue: Promise<unknown> = Promise.resolve();
    confirm = (c) => {
      const run = queue.then(async () => {
        const preview = JSON.stringify(c.params ?? null).slice(0, 300);
        const ans = await rl.question(`\nAllow ${c.cap}.${c.method} ${preview}? [y/N] `);
        return /^y(es)?$/i.test(ans.trim());
      });
      queue = run.catch(() => {});
      return run;
    };
  }

  // A saved (timed/trusted) link for this server is always reused. "once" links are never written to disk.
  const credentials = new FileCredentialStore();
  const prefix = f.get("prefix") as string | undefined;
  const saved = await credentials.load(makeAudience(server, prefix ?? "/hostlink"));
  if (saved && (saved.grant.expiresAt === null || saved.grant.expiresAt > Date.now())) {
    console.log(`  Using the saved ${saved.grant.mode} link for this server (${fmtExpiry(saved.grant.expiresAt)}). Run "hostlink forget ${server}" to remove it.`);
  }

  const agent = new HostlinkAgent({
    server, prefix, name: f.get("name") as string | undefined, credentials,
    mode, ttlSeconds, capabilities: caps, allowInsecure: f.has("insecure"), confirm,
    onCall: (c) => console.log(`  ${c.ok ? "✓" : "✗"} ${c.cap}.${c.method} ${c.ms}ms${c.error ? `  ${c.error.split("\n")[0]}` : ""}`),
  });
  agent.on("status", (s: AgentStatus) => {
    if (s.state === "pairing") {
      console.log(`\n  To link this machine, open on a device where you are signed in:\n\n    ${s.verificationUriComplete}\n\n  and check the code matches:  ${s.userCode}\n\n  (code valid for ${Math.round(s.expiresIn / 60)} min)\n`);
    } else if (s.state === "online") {
      console.log(`● Linked as ${s.deviceId}. Allowed: ${s.grant.scopes.join(", ")}. Mode ${s.grant.mode}, ${fmtExpiry(s.grant.expiresAt)}.`);
      console.log("  The remote agent can now act on this machine. Press Ctrl+C to disconnect.\n");
    } else if (s.state === "reconnecting") {
      console.log(`  Connection lost (${s.code}${s.reason ? ` ${s.reason}` : ""}), retrying in ${Math.ceil(s.inMs / 1000)}s`);
    } else if (s.state === "ended") {
      console.log(`● Link ended: ${s.reason}`);
    }
  });

  let stopping = false;
  const onSignal = () => {
    if (stopping) process.exit(130);
    stopping = true;
    console.log("\n  Disconnecting...");
    void agent.stop("stopped by user").then(() => process.exit(0));
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);

  await agent.start();
  const reason = await agent.done;
  process.exit(reason === "stopped by user" ? 0 : 1);
}

async function main() {
  const a = parseArgs(process.argv.slice(2));
  const cmd = a._[0];
  if (a.flags.has("version")) { console.log(VERSION); return; }
  if (!cmd || a.flags.has("help") || cmd === "help") { console.log(HELP); return; }
  if (cmd === "connect") return connect(a);
  if (cmd === "list") {
    const all = await new FileCredentialStore().list();
    if (!all.length) console.log("No saved links.");
    for (const c of all) console.log(`${c.audience}  ${c.deviceId}  ${c.grant.mode}  ${fmtExpiry(c.grant.expiresAt)}  scopes: ${c.grant.scopes.join(",")}`);
    return;
  }
  if (cmd === "forget") {
    const server = a._[1];
    if (!server) throw new HostlinkError("usage", "hostlink forget <server-url>");
    const aud = makeAudience(server, (a.flags.get("prefix") as string | undefined) ?? "/hostlink");
    await new FileCredentialStore().delete(aud);
    console.log(`Forgot ${aud}. Revoke it on the server too if it is still listed there.`);
    return;
  }
  throw new HostlinkError("usage", `Unknown command "${cmd}". Try hostlink --help`);
}

main().catch((e) => {
  console.error(`hostlink: ${(e as Error).message}`);
  process.exit(e instanceof HostlinkError && e.code === "usage" ? 2 : 1);
});
