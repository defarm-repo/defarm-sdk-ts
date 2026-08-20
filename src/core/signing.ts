import { ed25519 } from "@noble/curves/ed25519";
import {
  ED25519_SEED_LEN,
  SCHEMA_ENC_KEY_BINDING_V1,
  SEALER_SIG_ALG,
} from "./constants.js";
import { fromBase64, toBase64, utf8 } from "./encoding.js";
import { jcsSerialize } from "./jcs.js";
import type { SealedField, Wrap } from "./envelope.js";

/** Generate a fresh Ed25519 signing key pair (seed form, 32 bytes — same as ed25519-dalek). */
export function generateEd25519KeyPair(): {
  seed: Uint8Array;
  publicKey: Uint8Array;
} {
  const seed = crypto.getRandomValues(new Uint8Array(ED25519_SEED_LEN));
  return { seed, publicKey: ed25519.getPublicKey(seed) };
}

/** Derive the Ed25519 public key from a 32-byte seed. */
export function ed25519PublicKey(seed: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(seed);
}

/**
 * The canonical material (JCS) the SEALER signs: the whole envelope minus `sealer_sig_b64`.
 * Wraps are sorted by `(recipient_workspace_id, recipient_enc_key_id)` BEFORE serialization —
 * JCS canonicalizes object keys but never reorders arrays, so without this two implementations
 * could sign different bytes for the same delivery. Mirrors `canonical_sealer_signing_string`.
 */
/**
 * Code-point-wise string comparison (equivalent to Rust's `String::cmp`, which compares UTF-8
 * bytes — identical order to code points). NOT `localeCompare` (locale-dependent) and NOT plain
 * `<` on strings (UTF-16 code-unit order diverges from code-point order above U+FFFF).
 */
function cmpCodePoints(a: string, b: string): number {
  const ia = a[Symbol.iterator]();
  const ib = b[Symbol.iterator]();
  for (;;) {
    const ra = ia.next();
    const rb = ib.next();
    if (ra.done && rb.done) return 0;
    if (ra.done) return -1;
    if (rb.done) return 1;
    const ca = ra.value.codePointAt(0)!;
    const cb = rb.value.codePointAt(0)!;
    if (ca !== cb) return ca - cb;
  }
}

export function canonicalSealerSigningString(sealed: SealedField): string {
  const wraps = [...sealed.wraps].sort(
    (a, b) =>
      cmpCodePoints(a.recipient_workspace_id, b.recipient_workspace_id) ||
      cmpCodePoints(a.recipient_enc_key_id, b.recipient_enc_key_id),
  );
  const wrapsJson = wraps.map((w: Wrap) => ({
    recipient_workspace_id: w.recipient_workspace_id,
    recipient_enc_key_id: w.recipient_enc_key_id,
    kid_fingerprint: w.kid_fingerprint,
    hpke_enc_b64: w.hpke_enc_b64,
    wrapped_dk_b64: w.wrapped_dk_b64,
  }));
  return jcsSerialize({
    schema: sealed.schema,
    alg: sealed.alg,
    dfid: sealed.dfid,
    event_id: sealed.event_id,
    field_path: sealed.field_path,
    content_type: sealed.content_type,
    aad: sealed.aad,
    ciphertext_b64: sealed.ciphertext_b64,
    commitment_sha256: sealed.commitment_sha256,
    wraps: wrapsJson,
    sealer_workspace_id: sealed.sealer_workspace_id,
    sealer_key_id: sealed.sealer_key_id,
    sealer_sig_alg: sealed.sealer_sig_alg,
  });
}

/**
 * Sign a SealedField as the sealer — fills the identity fields and the Ed25519 signature over the
 * canonical signing string. The server NEVER runs this (it only verifies); this is the client-side
 * counterpart of `sign_sealed_field` in sealed_field.rs (the reference for SDKs, engines#542).
 */
export function signSealedField(
  sealed: SealedField,
  sealerWorkspaceId: string,
  sealerKeyId: string,
  ed25519Seed: Uint8Array,
): SealedField {
  const out: SealedField = {
    ...sealed,
    sealer_workspace_id: sealerWorkspaceId,
    sealer_key_id: sealerKeyId,
    sealer_sig_alg: SEALER_SIG_ALG,
    sealer_sig_b64: "",
  };
  const msg = canonicalSealerSigningString(out);
  out.sealer_sig_b64 = toBase64(ed25519.sign(utf8(msg), ed25519Seed));
  return out;
}

/** Verify the sealer signature against a TRUSTED Ed25519 public key. */
export function verifySealerSignature(
  sealed: SealedField,
  sealerEd25519PubB64: string,
): boolean {
  if (sealed.sealer_sig_alg !== SEALER_SIG_ALG) return false;
  try {
    const msg = canonicalSealerSigningString(sealed);
    return ed25519.verify(
      fromBase64(sealed.sealer_sig_b64),
      utf8(msg),
      fromBase64(sealerEd25519PubB64),
    );
  } catch {
    return false;
  }
}

/** Canonical binding (JCS) tying an X25519 encryption key to a workspace + key id. */
export function canonicalEncKeyBinding(
  workspaceId: string,
  encKeyId: string,
  encPubkeyB64: string,
): string {
  return jcsSerialize({
    schema: SCHEMA_ENC_KEY_BINDING_V1,
    workspace_id: workspaceId,
    enc_key_id: encKeyId,
    enc_pubkey_b64: encPubkeyB64.trim(),
  });
}

/** Sign the encryption-key binding with the workspace's Ed25519 identity (done at key registration). */
export function signEncKeyBinding(
  workspaceId: string,
  encKeyId: string,
  encPubkeyB64: string,
  ed25519Seed: Uint8Array,
): string {
  const binding = canonicalEncKeyBinding(workspaceId, encKeyId, encPubkeyB64);
  return toBase64(ed25519.sign(utf8(binding), ed25519Seed));
}

/**
 * Anti-MITM re-verification: before sealing to a public encryption key served by the directory,
 * the sealer re-derives the binding from the args (never trusts a passed-in string) and checks the
 * recipient's Ed25519 signature over it. If the directory swapped the lock, this fails.
 * Mirrors `verify_enc_key_binding` in sealed_field.rs.
 */
export function verifyEncKeyBinding(
  workspaceId: string,
  encKeyId: string,
  encPubkeyB64: string,
  ed25519SigB64: string,
  ed25519PubB64: string,
): boolean {
  try {
    const binding = canonicalEncKeyBinding(workspaceId, encKeyId, encPubkeyB64);
    return ed25519.verify(
      fromBase64(ed25519SigB64),
      utf8(binding),
      fromBase64(ed25519PubB64),
    );
  } catch {
    return false;
  }
}
