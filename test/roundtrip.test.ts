import { describe, expect, it } from "vitest";
import {
  ALG,
  HPKE_ENC_LEN,
  SCHEMA_SEALED_FIELD_V1,
  SEALER_SIG_ALG,
  WRAPPED_DK_LEN,
  ed25519PublicKey,
  fromBase64,
  generateEd25519KeyPair,
  generateX25519KeyPair,
  openField,
  sealField,
  signEncKeyBinding,
  signSealedField,
  toBase64,
  utf8,
  verifyEncKeyBinding,
  verifySealerSignature,
  x25519PublicKey,
} from "../src/core/index.js";
import { OpenFieldError } from "../src/core/open.js";

const CTX = {
  dfid: "DFID-DEFARM-BR-2026-000001-000001",
  eventId: "11111111-2222-3333-4444-555555555555",
  fieldPath: "preco_venda",
  contentType: "text/plain",
};
const PLAINTEXT = utf8("R$ 8.500,00");

async function sealForTwo() {
  const alice = generateX25519KeyPair(); // sealer's own key
  const bob = generateX25519KeyPair(); // recipient
  const sealed = await sealField(
    CTX.dfid,
    CTX.eventId,
    CTX.fieldPath,
    CTX.contentType,
    PLAINTEXT,
    [
      { workspaceId: "ws-alice", encKeyId: "enc-alice", encPubkeyB64: toBase64(alice.publicKey) },
      { workspaceId: "ws-bob", encKeyId: "enc-bob", encPubkeyB64: toBase64(bob.publicKey) },
    ],
  );
  return { alice, bob, sealed };
}

describe("seal → open roundtrip", () => {
  it("both addressed recipients open; sizes match the suite exactly", async () => {
    const { alice, bob, sealed } = await sealForTwo();

    expect(sealed.schema).toBe(SCHEMA_SEALED_FIELD_V1);
    expect(sealed.alg).toBe(ALG);
    expect(sealed.commitment_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(sealed.wraps).toHaveLength(2);
    for (const w of sealed.wraps) {
      // Sizes fixed by the suite — the server rejects anything else (engines#533).
      expect(fromBase64(w.hpke_enc_b64)).toHaveLength(HPKE_ENC_LEN);
      expect(fromBase64(w.wrapped_dk_b64)).toHaveLength(WRAPPED_DK_LEN);
      expect(w.kid_fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/);
    }
    // nonce(12) + ciphertext + tag(16)
    expect(fromBase64(sealed.ciphertext_b64).length).toBe(12 + PLAINTEXT.length + 16);

    const fromAlice = await openField(sealed, "enc-alice", alice.privateKey);
    const fromBob = await openField(sealed, "enc-bob", bob.privateKey);
    expect(fromAlice).toEqual(PLAINTEXT);
    expect(fromBob).toEqual(PLAINTEXT);
  });

  it("a non-addressed key cannot open (no wrap)", async () => {
    const { sealed } = await sealForTwo();
    const eve = generateX25519KeyPair();
    await expect(openField(sealed, "enc-eve", eve.privateKey)).rejects.toThrow(
      /no_wrap_for_recipient/,
    );
  });

  it("the wrong private key fails at HPKE, even claiming an addressed key id", async () => {
    const { sealed } = await sealForTwo();
    const eve = generateX25519KeyPair();
    await expect(openField(sealed, "enc-bob", eve.privateKey)).rejects.toThrow(/hpke_open/);
  });

  it("tampering with any bound context field fails the open (anti-frankenstein)", async () => {
    const { bob, sealed } = await sealForTwo();
    for (const tamper of [
      { ...sealed, dfid: "DFID-DEFARM-BR-2026-999999-999999" },
      { ...sealed, field_path: "peso" },
      { ...sealed, event_id: "99999999-0000-0000-0000-000000000000" },
      { ...sealed, content_type: "application/json" },
    ]) {
      await expect(openField(tamper, "enc-bob", bob.privateKey)).rejects.toThrow(OpenFieldError);
    }
  });

  it("two seals of the same plaintext give different commitments (no correlation)", async () => {
    const bob = generateX25519KeyPair();
    const r = [{ workspaceId: "ws-bob", encKeyId: "enc-bob", encPubkeyB64: toBase64(bob.publicKey) }];
    const a = await sealField(CTX.dfid, CTX.eventId, CTX.fieldPath, CTX.contentType, PLAINTEXT, r);
    const b = await sealField(CTX.dfid, CTX.eventId, CTX.fieldPath, CTX.contentType, PLAINTEXT, r);
    expect(a.commitment_sha256).not.toBe(b.commitment_sha256);
  });
});

describe("sealer signature (ed25519_jcs_v1)", () => {
  it("signs and verifies; any envelope mutation invalidates", async () => {
    const { sealed } = await sealForTwo();
    const signer = generateEd25519KeyPair();
    const signedEnv = signSealedField(sealed, "ws-alice", "sign-alice", signer.seed);

    expect(signedEnv.sealer_sig_alg).toBe(SEALER_SIG_ALG);
    const pubB64 = toBase64(signer.publicKey);
    expect(verifySealerSignature(signedEnv, pubB64)).toBe(true);

    // Mutations that must invalidate: content, delivery (wraps), declared identity.
    expect(
      verifySealerSignature({ ...signedEnv, commitment_sha256: "0".repeat(64) }, pubB64),
    ).toBe(false);
    expect(
      verifySealerSignature({ ...signedEnv, wraps: signedEnv.wraps.slice(0, 1) }, pubB64),
    ).toBe(false);
    expect(
      verifySealerSignature({ ...signedEnv, sealer_workspace_id: "ws-mallory" }, pubB64),
    ).toBe(false);
    // Wrong public key.
    const other = generateEd25519KeyPair();
    expect(verifySealerSignature(signedEnv, toBase64(other.publicKey))).toBe(false);
  });

  it("wrap order does not change the signed bytes (sorted before JCS)", async () => {
    const { sealed } = await sealForTwo();
    const signer = generateEd25519KeyPair();
    const signedEnv = signSealedField(sealed, "ws-alice", "sign-alice", signer.seed);
    const reordered = { ...signedEnv, wraps: [...signedEnv.wraps].reverse() };
    expect(verifySealerSignature(reordered, toBase64(signer.publicKey))).toBe(true);
  });
});

describe("encryption-key binding", () => {
  it("verifies a genuine binding and rejects a re-targeted one", () => {
    const identity = generateEd25519KeyPair();
    const enc = generateX25519KeyPair();
    const pubB64 = toBase64(x25519PublicKey(enc.privateKey));
    const idPubB64 = toBase64(ed25519PublicKey(identity.seed));

    const sig = signEncKeyBinding("ws-bob", "enc-bob", pubB64, identity.seed);
    expect(verifyEncKeyBinding("ws-bob", "enc-bob", pubB64, sig, idPubB64)).toBe(true);

    // A valid signature for (wsA, kA, pub) must NOT vouch for another workspace, key id, or key.
    expect(verifyEncKeyBinding("ws-victim", "enc-bob", pubB64, sig, idPubB64)).toBe(false);
    expect(verifyEncKeyBinding("ws-bob", "enc-other", pubB64, sig, idPubB64)).toBe(false);
    const otherKey = toBase64(generateX25519KeyPair().publicKey);
    expect(verifyEncKeyBinding("ws-bob", "enc-bob", otherKey, sig, idPubB64)).toBe(false);
  });
});
