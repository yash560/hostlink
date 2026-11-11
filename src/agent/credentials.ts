import { mkdir, readFile, rename, writeFile, chmod } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { Grant } from "../protocol.js";

export interface StoredCredential {
  v: 1;
  audience: string;
  deviceId: string;
  /** PKCS8 DER, base64url. */
  privateKey: string;
  grant: Grant;
  name: string;
  savedAt: number;
}

export interface CredentialStore {
  load(audience: string): Promise<StoredCredential | null>;
  save(c: StoredCredential): Promise<void>;
  delete(audience: string): Promise<void>;
  list(): Promise<StoredCredential[]>;
}

export class MemoryCredentialStore implements CredentialStore {
  private m = new Map<string, StoredCredential>();
  async load(a: string) { return this.m.get(a) ?? null; }
  async save(c: StoredCredential) { this.m.set(c.audience, c); }
  async delete(a: string) { this.m.delete(a); }
  async list() { return [...this.m.values()]; }
}

export function defaultCredentialPath(): string {
  if (process.env.HOSTLINK_HOME) return join(process.env.HOSTLINK_HOME, "credentials.json");
  if (process.platform === "win32" && process.env.APPDATA) return join(process.env.APPDATA, "hostlink", "credentials.json");
  const base = process.env.XDG_CONFIG_HOME || join(homedir(), ".config");
  return join(base, "hostlink", "credentials.json");
}

/** Stores device keys in a JSON file readable only by the current user (0600, directory 0700). */
export class FileCredentialStore implements CredentialStore {
  private chain: Promise<unknown> = Promise.resolve();
  constructor(readonly path: string = defaultCredentialPath()) {}

  private async read(): Promise<Record<string, StoredCredential>> {
    try {
      const data = JSON.parse(await readFile(this.path, "utf8")) as { credentials?: Record<string, StoredCredential> };
      return data.credentials ?? {};
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return {};
      throw e;
    }
  }

  private async write(all: Record<string, StoredCredential>) {
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    const tmp = `${this.path}.${process.pid}.tmp`;
    await writeFile(tmp, JSON.stringify({ v: 1, credentials: all }, null, 2), { mode: 0o600 });
    await chmod(tmp, 0o600).catch(() => {});
    await rename(tmp, this.path);
  }

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(fn, fn);
    this.chain = run.catch(() => {});
    return run;
  }

  load(audience: string) { return this.serial(async () => (await this.read())[audience] ?? null); }
  save(c: StoredCredential) { return this.serial(async () => { const all = await this.read(); all[c.audience] = c; await this.write(all); }); }
  delete(audience: string) {
    return this.serial(async () => {
      const all = await this.read();
      if (!(audience in all)) return;
      delete all[audience];
      await this.write(all);
    });
  }
  list() { return this.serial(async () => Object.values(await this.read())); }
}
