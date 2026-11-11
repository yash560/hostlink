import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { DeviceInfo, Grant, GrantMode } from "../protocol.js";

export type PairingStatus = "pending" | "approved" | "denied";

export interface PairingRecord {
  id: string;
  deviceCodeHash: string;
  userCodeHash: string;
  publicKey: string;
  device: DeviceInfo;
  ip: string;
  requested: { scopes: string[]; mode: GrantMode; ttlSeconds: number | null };
  status: PairingStatus;
  createdAt: number;
  expiresAt: number;
  interval: number;
  lastPolledAt: number | null;
  /** Set on approval. */
  ownerId?: string;
  deviceId?: string;
  grant?: Grant;
}

export interface DeviceRecord {
  id: string;
  ownerId: string;
  publicKey: string;
  device: DeviceInfo;
  grant: Grant;
  pairedAt: number;
  pairedFromIp: string;
  lastSeenAt: number;
  lastSeenIp: string | null;
}

/**
 * Persistence used by the server. Implement this against your own database.
 * Every method may be async. `updatePairingIf` and `updateDevice` must be atomic
 * (compare-and-set), e.g. MongoDB findOneAndUpdate with the status in the filter.
 */
export interface HostlinkStore {
  createPairing(p: PairingRecord): Promise<void>;
  findPairingByDeviceCode(deviceCodeHash: string): Promise<PairingRecord | null>;
  findPairingByUserCode(userCodeHash: string): Promise<PairingRecord | null>;
  /** Applies `patch` only if the record still has `expectedStatus`. Returns the updated record or null. */
  updatePairingIf(id: string, expectedStatus: PairingStatus, patch: Partial<PairingRecord>): Promise<PairingRecord | null>;
  /** Unconditional patch (used for poll bookkeeping). */
  touchPairing(id: string, patch: Pick<PairingRecord, "lastPolledAt" | "interval">): Promise<void>;
  deletePairing(id: string): Promise<void>;
  /** Removes pairings whose expiresAt is before `now`. */
  deleteExpiredPairings(now: number): Promise<void>;

  /** Insert or replace by id (must be idempotent). */
  putDevice(d: DeviceRecord): Promise<void>;
  getDevice(id: string): Promise<DeviceRecord | null>;
  listDevices(filter: { ownerId?: string; mode?: GrantMode }): Promise<DeviceRecord[]>;
  updateDevice(id: string, patch: Partial<Pick<DeviceRecord, "lastSeenAt" | "lastSeenIp" | "grant" | "device">>): Promise<void>;
  /** Returns true if a record was deleted. */
  deleteDevice(id: string): Promise<boolean>;
}

const clone = <T>(v: T): T => structuredClone(v);

/** In-memory store. Fine for tests and single-process servers that accept losing devices on restart. */
export class MemoryStore implements HostlinkStore {
  protected pairings = new Map<string, PairingRecord>();
  protected devices = new Map<string, DeviceRecord>();

  async createPairing(p: PairingRecord) {
    this.pairings.set(p.id, clone(p));
    await this.persist();
  }
  async findPairingByDeviceCode(h: string) {
    for (const p of this.pairings.values()) if (p.deviceCodeHash === h) return clone(p);
    return null;
  }
  async findPairingByUserCode(h: string) {
    for (const p of this.pairings.values()) if (p.userCodeHash === h) return clone(p);
    return null;
  }
  async updatePairingIf(id: string, expected: PairingStatus, patch: Partial<PairingRecord>) {
    const p = this.pairings.get(id);
    if (!p || p.status !== expected) return null;
    const next = { ...p, ...clone(patch), id: p.id };
    this.pairings.set(id, next);
    await this.persist();
    return clone(next);
  }
  async touchPairing(id: string, patch: Pick<PairingRecord, "lastPolledAt" | "interval">) {
    const p = this.pairings.get(id);
    if (p) this.pairings.set(id, { ...p, ...patch });
  }
  async deletePairing(id: string) {
    if (this.pairings.delete(id)) await this.persist();
  }
  async deleteExpiredPairings(now: number) {
    let changed = false;
    for (const [id, p] of this.pairings) if (p.expiresAt < now) { this.pairings.delete(id); changed = true; }
    if (changed) await this.persist();
  }
  async putDevice(d: DeviceRecord) {
    this.devices.set(d.id, clone(d));
    await this.persist();
  }
  async getDevice(id: string) {
    const d = this.devices.get(id);
    return d ? clone(d) : null;
  }
  async listDevices(filter: { ownerId?: string; mode?: GrantMode }) {
    return [...this.devices.values()]
      .filter((d) => (filter.ownerId === undefined || d.ownerId === filter.ownerId) && (filter.mode === undefined || d.grant.mode === filter.mode))
      .map(clone);
  }
  async updateDevice(id: string, patch: Partial<Pick<DeviceRecord, "lastSeenAt" | "lastSeenIp" | "grant" | "device">>) {
    const d = this.devices.get(id);
    if (!d) return;
    this.devices.set(id, { ...d, ...clone(patch) });
    await this.persist();
  }
  async deleteDevice(id: string) {
    const had = this.devices.delete(id);
    if (had) await this.persist();
    return had;
  }
  protected async persist(): Promise<void> {}
}

/**
 * JSON-file store for small self-hosted servers. Writes are serialised and atomic (write + rename).
 * Pairings are kept in memory only (they live for minutes); devices are persisted.
 */
export class FileStore extends MemoryStore {
  private chain: Promise<void> = Promise.resolve();
  private constructor(private readonly path: string) {
    super();
  }

  static async open(path: string): Promise<FileStore> {
    const s = new FileStore(path);
    try {
      const data = JSON.parse(await readFile(path, "utf8")) as { devices?: DeviceRecord[] };
      for (const d of data.devices ?? []) s.devices.set(d.id, d);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    }
    return s;
  }

  protected override persist(): Promise<void> {
    const snapshot = JSON.stringify({ v: 1, devices: [...this.devices.values()] }, null, 2);
    const run = async () => {
      await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
      const tmp = `${this.path}.${process.pid}.tmp`;
      await writeFile(tmp, snapshot, { mode: 0o600 });
      await rename(tmp, this.path);
    };
    this.chain = this.chain.then(run, run);
    return this.chain;
  }
}
