import { mkdtempSync, statSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { FileKeystore } from "../src/keystore.js";

/**
 * Issue #6: FileKeystore's read-modify-write must survive concurrency. Losing the race can drop
 * a private key from the file — and a dropped encryption key means the fields sealed to it are
 * gone for good (the server holds no copy; that is the design).
 */
describe("FileKeystore concurrency and tmp hygiene (issue #6)", () => {
  it("concurrent puts of both kinds keep BOTH keys", async () => {
    const dir = mkdtempSync(join(tmpdir(), "defarm-ks-"));
    const ks = new FileKeystore(join(dir, "keys.json"));
    await Promise.all([
      ks.put("signing", { keyId: "sign-1", privateKey: new Uint8Array(32).fill(1) }),
      ks.put("encryption", { keyId: "enc-1", privateKey: new Uint8Array(32).fill(2) }),
    ]);
    expect((await ks.get("signing"))?.keyId).toBe("sign-1");
    expect((await ks.get("encryption"))?.keyId).toBe("enc-1");
  });

  it("two instances on the same file do not lose writes (lockfile path)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "defarm-ks-"));
    const file = join(dir, "keys.json");
    const a = new FileKeystore(file);
    const b = new FileKeystore(file);
    await Promise.all([
      a.put("signing", { keyId: "sign-a", privateKey: new Uint8Array(32).fill(3) }),
      b.put("encryption", { keyId: "enc-b", privateKey: new Uint8Array(32).fill(4) }),
    ]);
    const final = JSON.parse(await readFile(file, "utf8"));
    expect(Object.keys(final.keys).sort()).toEqual(["encryption", "signing"]);
  });

  it("keystore file lands with 0600 and a stale .tmp is never reused", async () => {
    const dir = mkdtempSync(join(tmpdir(), "defarm-ks-"));
    const file = join(dir, "keys.json");
    // A crash leftover with loose permissions under the OLD fixed tmp name.
    await writeFile(`${file}.tmp`, "{}", { mode: 0o644 });
    const ks = new FileKeystore(file);
    await ks.put("signing", { keyId: "sign-1", privateKey: new Uint8Array(32).fill(5) });
    expect(statSync(file).mode & 0o777).toBe(0o600);
    // The stale tmp was not the write path (file content is the real keystore).
    const data = JSON.parse(await readFile(file, "utf8"));
    expect(data.keys.signing.key_id).toBe("sign-1");
  });

  it("a stale lockfile (crashed holder) is taken over instead of deadlocking", async () => {
    const dir = mkdtempSync(join(tmpdir(), "defarm-ks-"));
    const file = join(dir, "keys.json");
    const fs = await import("node:fs/promises");
    await writeFile(`${file}.lock`, "");
    const past = new Date(Date.now() - 60_000);
    await fs.utimes(`${file}.lock`, past, past);
    const ks = new FileKeystore(file);
    await ks.put("signing", { keyId: "sign-1", privateKey: new Uint8Array(32).fill(6) });
    expect((await ks.get("signing"))?.keyId).toBe("sign-1");
  });
});
