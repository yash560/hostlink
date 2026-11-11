/**
 * Wire protocol shared by the hostlink server and agent.
 * See PROTOCOL.md for the full description.
 */
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign, verify, timingSafeEqual, type KeyObject } from "node:crypto";

export const PROTOCOL_VERSION = 1;

export type GrantMode = "once" | "timed" | "trusted";
export const GRANT_MODES: readonly GrantMode[] = ["once", "timed", "trusted"];

export interface Grant {
  /** Capability names the device may be asked to use. */
  scopes: string[];
  mode: GrantMode;
  /** Epoch ms, or null for a lifetime grant (only if the server policy allows it). */
  expiresAt: number | null;
}

export interface CapabilityDescriptor {
  name: string;
  methods: string[];
}

export interface DeviceInfo {
  name: string;
  platform: string;
  arch: string;
  agentVersion: string;
}

/** Close codes used on the WebSocket. 4xxx = do not reconnect, unless listed as retryable. */
export const CloseCode = {
  ProtocolError: 4400,
  Unauthorized: 4401,
  Revoked: 4403,
  AuthTimeout: 4408,
  Replaced: 4409,
  Expired: 4410,
  ServerShutdown: 4503,
} as const;

/** Codes after which the agent must stop and forget its credential. */
export const TERMINAL_CLOSE_CODES: ReadonlySet<number> = new Set([CloseCode.Unauthorized, CloseCode.Revoked, CloseCode.Expired]);

// ---------- HTTP bodies ----------

export interface PairStartRequest {
  v: number;
  publicKey: string; // base64url raw 32-byte Ed25519 public key
  device: DeviceInfo;
  requested: { scopes: string[]; mode: GrantMode; ttlSeconds: number | null };
}

export interface PairStartResponse {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string;
  expiresIn: number;
  interval: number;
}

export type PairPollResponse =
  | { status: "pending" }
  | { status: "slow_down"; interval: number }
  | { status: "denied" }
  | { status: "expired" }
  | { status: "approved"; deviceId: string; grant: Grant };

// ---------- WebSocket frames ----------

export type ServerFrame =
  | { t: "challenge"; v: number; nonce: string }
  | { t: "ready"; sessionId: string; deviceId: string; grant: Grant }
  | { t: "call"; id: string; cap: string; method: string; params: unknown }
  | { t: "cancel"; id: string };

export type AgentFrame =
  | { t: "auth"; v: number; deviceId: string; sig: string; capabilities: CapabilityDescriptor[]; device: DeviceInfo }
  | { t: "result"; id: string; ok: true; value: unknown }
  | { t: "result"; id: string; ok: false; error: { code: string; message: string } }
  | { t: "bye" };

// ---------- Errors ----------

export class HostlinkError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, message: string, status = 400) {
    super(message);
    this.name = "HostlinkError";
    this.code = code;
    this.status = status;
  }
}

// ---------- Crypto helpers ----------

export function b64url(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString("base64url");
}

export function fromB64url(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

export function randomToken(bytes = 32): string {
  return b64url(randomBytes(bytes));
}

export function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface DeviceKeyPair {
  privateKey: KeyObject;
  /** base64url raw public key */
  publicKey: string;
}

export function generateDeviceKey(): DeviceKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicKey: rawPublicKey(publicKey) };
}

export function rawPublicKey(key: KeyObject): string {
  const spki = key.export({ type: "spki", format: "der" });
  return b64url(spki.subarray(ED25519_SPKI_PREFIX.length));
}

export function publicKeyFromRaw(raw: string): KeyObject {
  const bytes = fromB64url(raw);
  if (bytes.length !== 32 || b64url(bytes) !== raw) throw new HostlinkError("invalid_public_key", "publicKey must be a base64url 32-byte Ed25519 key");
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, bytes]), format: "der", type: "spki" });
}

export function exportPrivateKey(key: KeyObject): string {
  return b64url(key.export({ type: "pkcs8", format: "der" }));
}

export function importPrivateKey(s: string): KeyObject {
  return createPrivateKey({ key: fromB64url(s), format: "der", type: "pkcs8" });
}

/**
 * The exact bytes an agent signs to prove it holds the device key.
 * `audience` is the origin + prefix the agent was configured with (never taken from the server),
 * so a signature produced for one server cannot be replayed against another.
 */
export function authMessage(audience: string, deviceId: string, nonce: string): Buffer {
  return Buffer.from(`hostlink-auth-v${PROTOCOL_VERSION}\n${audience}\n${deviceId}\n${nonce}`, "utf8");
}

export function signAuth(privateKey: KeyObject, audience: string, deviceId: string, nonce: string): string {
  return b64url(sign(null, authMessage(audience, deviceId, nonce), privateKey));
}

export function verifyAuth(publicKey: KeyObject, audience: string, deviceId: string, nonce: string, sig: string): boolean {
  try {
    const sigBytes = fromB64url(sig);
    if (sigBytes.length !== 64) return false;
    return verify(null, authMessage(audience, deviceId, nonce), publicKey, sigBytes);
  } catch {
    return false;
  }
}

/** Normalises an origin + path prefix into the canonical audience string. */
export function makeAudience(origin: string, prefix: string): string {
  const u = new URL(origin);
  return `${u.protocol}//${u.host}${normalizePrefix(prefix)}`;
}

export function normalizePrefix(prefix: string): string {
  let p = prefix.trim();
  if (!p.startsWith("/")) p = "/" + p;
  while (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  return p === "/" ? "" : p;
}

// ---------- Validation ----------

export const SCOPE_RE = /^[a-z][a-z0-9_-]{0,31}$/;
export const METHOD_RE = /^[a-zA-Z][a-zA-Z0-9_]{0,63}$/;

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function cleanText(v: unknown, max: number, fallback = ""): string {
  if (typeof v !== "string") return fallback;
  // strip control characters so names render safely in approval screens and logs
  const s = v.replace(/[\u0000-\u001f\u007f‪-‮⁦-⁩]/g, "").trim();
  return s.slice(0, max) || fallback;
}

/** User codes: 8 letters from an alphabet without vowels or look-alikes, shown as XXXX-XXXX. */
export const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ";

export function generateUserCode(): string {
  const out: string[] = [];
  while (out.length < 8) {
    const b = randomBytes(16);
    for (const byte of b) {
      // rejection sampling keeps the distribution uniform (20 * 12 = 240)
      if (byte < 240 && out.length < 8) out.push(USER_CODE_ALPHABET[byte % 20]!);
    }
  }
  return `${out.slice(0, 4).join("")}-${out.slice(4).join("")}`;
}

/** Accepts "bcdf ghjk", "BCDF-GHJK" etc. Returns null if it cannot be a valid code. */
export function normalizeUserCode(input: string): string | null {
  const letters = input.toUpperCase().replace(/[^A-Z]/g, "");
  if (letters.length !== 8) return null;
  for (const c of letters) if (!USER_CODE_ALPHABET.includes(c)) return null;
  return `${letters.slice(0, 4)}-${letters.slice(4)}`;
}

export function parseDuration(s: string): number {
  const m = /^(\d+)\s*(s|m|h|d)$/.exec(s.trim().toLowerCase());
  if (!m) throw new HostlinkError("invalid_duration", `Cannot parse duration "${s}" (use e.g. 30m, 24h, 90d)`);
  const n = Number(m[1]);
  const mult = { s: 1, m: 60, h: 3600, d: 86400 }[m[2] as "s" | "m" | "h" | "d"];
  if (n <= 0) throw new HostlinkError("invalid_duration", "Duration must be positive");
  return n * mult;
}
