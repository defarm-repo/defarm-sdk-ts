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
}

export class MemoryKeystore implements Keystore {
  private keys = new Map<KeyKind, StoredKey>();

  async get(kind: KeyKind): Promise<StoredKey | null> {
    return this.keys.get(kind) ?? null;
  }

  async put(kind: KeyKind, key: StoredKey): Promise<void> {
    this.keys.set(kind, key);
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
  constructor(private readonly path: string) {}

  static async defaultPath(): Promise<string> {
    const os = await import("node:os");
    const path = await import("node:path");
    return path.join(os.homedir(), ".defarm", "keys.json");
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

  async put(kind: KeyKind, key: StoredKey): Promise<void> {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");
    const data = await this.load();
    data.keys[kind] = {
      key_id: key.keyId,
      private_key_b64: toBase64(key.privateKey),
    };
    await fs.mkdir(path.dirname(this.path), { recursive: true, mode: 0o700 });
    const tmp = `${this.path}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
    await fs.rename(tmp, this.path);
  }
}
