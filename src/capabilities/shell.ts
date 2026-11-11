import { spawn } from "node:child_process";
import { HostlinkError } from "../protocol.js";
import { num, obj, str } from "./params.js";
import type { Capability, CallContext } from "../agent/index.js";

export interface ShellOptions {
  /** Working directory used when a call gives none. Default: process.cwd(). */
  cwd?: string;
  /** Per-stream output cap. Default 1 MiB. */
  maxOutputBytes?: number;
  defaultTimeoutMs?: number;
  maxTimeoutMs?: number;
  /** Allow `script` (runs through /bin/sh or cmd.exe). Default true. */
  allowScripts?: boolean;
}

export interface ShellResult {
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  timedOut: boolean;
}

/** Runs commands on the device. Grant the "shell" scope only to devices you own. */
export function shellCapability(opts: ShellOptions = {}): Capability {
  const maxOut = opts.maxOutputBytes ?? 1024 * 1024;
  const defTimeout = opts.defaultTimeoutMs ?? 60_000;
  const maxTimeout = opts.maxTimeoutMs ?? 10 * 60_000;

  const common = (p: Record<string, unknown>) => {
    const cwd = p.cwd === undefined ? opts.cwd ?? process.cwd() : str(p.cwd, "cwd", 4096);
    const timeoutMs = p.timeoutMs === undefined ? defTimeout : num(p.timeoutMs, "timeoutMs", 1, maxTimeout);
    const input = p.input === undefined ? undefined : str(p.input, "input", maxOut);
    return { cwd, timeoutMs, input };
  };

  const methods: Capability["methods"] = {
    /** Runs a program directly (no shell): { command: ["git", "status"], cwd?, timeoutMs?, input? } */
    run: (params: unknown, ctx: CallContext) => {
      const p = obj(params);
      if (!Array.isArray(p.command) || p.command.length === 0 || p.command.length > 1000 || !p.command.every((a) => typeof a === "string")) {
        throw new HostlinkError("invalid_params", "command must be a non-empty array of strings");
      }
      const [file, ...args] = p.command as string[];
      return exec(file!, args, { ...common(p), maxOut, shell: false }, ctx.signal);
    },
  };
  if (opts.allowScripts !== false) {
    /** Runs a shell script: { script: "ls -la | head", cwd?, timeoutMs?, input? } */
    methods.script = (params: unknown, ctx: CallContext) => {
      const p = obj(params);
      const script = str(p.script, "script", 100_000);
      const [file, args] = process.platform === "win32" ? ["cmd.exe", ["/d", "/s", "/c", script]] : ["/bin/sh", ["-c", script]];
      return exec(file, args, { ...common(p), maxOut, shell: false }, ctx.signal);
    };
  }
  return { name: "shell", methods };
}

function exec(file: string, args: string[], o: { cwd: string; timeoutMs: number; input?: string; maxOut: number; shell: false }, signal: AbortSignal): Promise<ShellResult> {
  return new Promise((resolve, reject) => {
    const posix = process.platform !== "win32";
    const child = spawn(file, args, { cwd: o.cwd, shell: false, detached: posix, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let outLen = 0, errLen = 0, truncated = false, timedOut = false, done = false;
    const kill = () => {
      try {
        if (posix && child.pid) process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch { /* already gone */ }
    };
    const take = (buf: Buffer, into: Buffer[], len: number) => {
      const room = o.maxOut - len;
      if (room <= 0) { truncated = true; return len; }
      if (buf.length > room) { truncated = true; into.push(buf.subarray(0, room)); return o.maxOut; }
      into.push(buf);
      return len + buf.length;
    };
    child.stdout.on("data", (b: Buffer) => { outLen = take(b, out, outLen); });
    child.stderr.on("data", (b: Buffer) => { errLen = take(b, err, errLen); });
    const timer = setTimeout(() => { timedOut = true; kill(); }, o.timeoutMs);
    const onAbort = () => kill();
    signal.addEventListener("abort", onAbort, { once: true });
    child.on("error", (e) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      reject(new HostlinkError("spawn_failed", e.message));
    });
    child.on("close", (code, sig) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      resolve({ exitCode: code, signal: sig, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8"), truncated, timedOut });
    });
    child.stdin.on("error", () => {});
    if (o.input !== undefined) child.stdin.end(o.input);
    else child.stdin.end();
  });
}
