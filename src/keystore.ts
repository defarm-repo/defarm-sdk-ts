import { KeystoreError } from "./errors.js";
import { fromBase64, toBase64 } from "./core/encoding.js";

/**
 * Where private keys live. HARD RULE: private key material never leaves the producer's side —
 * it is generated here and stays here. The SDK ships a file keystore (server-side integrations)
 * and an in-memory one (tests, ephemeral flows); an ERP with an HSM implements this interface.
 *
 * Kinds: `signing` = Ed25519 seed (authorship — gives ZERO decryption power);
 *        `encryption` = X25519 private key (unwrap/decrypt).
 */
export type KeyKind = "signing" | "encryption";

export interface StoredKey {
  keyId: string;
  privateKey: Uint8Array;
}

export interface Keystore {
  get(kind: KeyKind): Promise<StoredKey | null>;
  put(kind: KeyKind, key: StoredKey): Promise<void>;
  /**
   * Atomically return the existing key or create-and-store one — the WHOLE get→create→put cycle
   * under the keystore's lock (issue #8). Two concurrent callers must end up with the SAME key:
   * a lost generated key means every field sealed to it is unrecoverable (the server holds no
   * copy; that is the design), so the factory must run at most once per stored key.
   */
  getOrCreate(kind: KeyKind, factory: () => StoredKey | Promise<StoredKey>): Promise<StoredKey>;
}

export class MemoryKeystore implements Keystore {
  private keys = new Map<KeyKind, StoredKey>();
  private queue: Promise<unknown> = Promise.resolve();

  async get(kind: KeyKind): Promise<StoredKey | null> {
    return this.keys.get(kind) ?? null;
  }

  async put(kind: KeyKind, key: StoredKey): Promise<void> {
    this.keys.set(kind, key);
  }

  async getOrCreate(
    kind: KeyKind,
    factory: () => StoredKey | Promise<StoredKey>,
  ): Promise<StoredKey> {
    const run = this.queue.then(async () => {
      const existing = this.keys.get(kind);
      if (existing) return existing;
      const created = await factory();
      this.keys.set(kind, created);
      return created;
    });
    this.queue = run.catch(() => undefined);
    return run;
  }
}

interface FileKeystoreShape {
  version: 1;
  keys: Partial<Record<KeyKind, { key_id: string; private_key_b64: string }>>;
}

/**
 * JSON file keystore for server-side/CLI use. The file is chmod 0600 and holds the ONLY copy of
 * the private keys — losing it means losing the ability to open fields sealed to those keys
 * (the DeFarm server cannot recover them; that is the whole point).
 */
export class FileKeystore implements Keystore {
  /** In-process serialization of read-modify-write cycles (issue #6). */
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private readonly path: string) {}

  static async defaultPath(): Promise<string> {
    const os = await import("node:os");
    const path = await import("node:path");
    return path.join(os.homedir(), ".defarm", "keys.json");
  }

  /**
   * Serialize the read-modify-write against BOTH concurrency axes (issue #6): an in-process
   * promise queue (two `put`s in the same process) and a cross-process `O_EXCL` lockfile. Losing
   * this race can drop a private key from the file — and a dropped encryption key means the
   * fields sealed to it are unrecoverable (the server holds no copy; that is the design).
   * The lockfile is taken over when older than 10s (crashed holder) and acquisition times out
   * loudly rather than deadlocking.
   */
  private async withLock<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(async () => {
      const fs = await import("node:fs/promises");
      const lockPath = `${this.path}.lock`;
      const path = await import("node:path");
      await fs.mkdir(path.dirname(this.path), { recursive: true, mode: 0o700 });
      const deadline = Date.now() + 5_000;
      for (;;) {
        try {
          const h = await fs.open(lockPath, "wx", 0o600);
          await h.close();
          break;
        } catch (e: unknown) {
          if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
          try {
            const st = await fs.stat(lockPath);
            if (Date.now() - st.mtimeMs > 10_000) {
              await fs.rm(lockPath, { force: true });
              continue;
            }
          } catch {
            continue; // lock vanished between open and stat — retry immediately
          }
          if (Date.now() > deadline) {
            throw new KeystoreError(
              `timed out acquiring keystore lock ${lockPath} — remove it if no other process is running`,
            );
          }
          await new Promise((r) => setTimeout(r, 50));
        }
      }
      try {
        return await fn();
      } finally {
        await fs.rm(lockPath, { force: true });
      }
    });
    // Keep the chain alive even when this cycle fails.
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async load(): Promise<FileKeystoreShape> {
    const fs = await import("node:fs/promises");
    try {
      const raw = await fs.readFile(this.path, "utf8");
      const parsed = JSON.parse(raw) as FileKeystoreShape;
      if (parsed.version !== 1) {
        throw new KeystoreError(`unsupported keystore version in ${this.path}`);
      }
      return parsed;
    } catch (e: unknown) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") {
        return { version: 1, keys: {} };
      }
      throw e;
    }
  }

  async get(kind: KeyKind): Promise<StoredKey | null> {
    const data = await this.load();
    const entry = data.keys[kind];
    if (!entry) return null;
    return { keyId: entry.key_id, privateKey: fromBase64(entry.private_key_b64) };
  }

  /** Write the full keystore atomically. MUST be called while holding the lock. */
  private async writeLocked(data: FileKeystoreShape): Promise<void> {
    const fs = await import("node:fs/promises");
    const crypto = await import("node:crypto");
    // Unique tmp name + `wx`: a stale .tmp from a crash (possibly with looser permissions)
    // is never reused — `mode` only applies on CREATION (issue #6).
    const tmp = `${this.path}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(data, null, 2), { mode: 0o600, flag: "wx" });
    await fs.rename(tmp, this.path);
  }

  async put(kind: KeyKind, key: StoredKey): Promise<void> {
    await this.withLock(async () => {
      const data = await this.load();
      data.keys[kind] = {
        key_id: key.keyId,
        private_key_b64: toBase64(key.privateKey),
      };
      await this.writeLocked(data);
    });
  }

  async getOrCreate(
    kind: KeyKind,
    factory: () => StoredKey | Promise<StoredKey>,
  ): Promise<StoredKey> {
    return this.withLock(async () => {
      const data = await this.load();
      const entry = data.keys[kind];
      if (entry) {
        return { keyId: entry.key_id, privateKey: fromBase64(entry.private_key_b64) };
      }
      const created = await factory();
      data.keys[kind] = {
        key_id: created.keyId,
        private_key_b64: toBase64(created.privateKey),
      };
      await this.writeLocked(data);
      return created;
    });
  }
}
