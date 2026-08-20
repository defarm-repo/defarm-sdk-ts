/**
 * Wire-format constants. These MUST match the Rust oracle
 * (`engines/services/layer-2-registry/item-registry/src/api/sealed_field.rs`)
 * byte-for-byte — the server rejects anything else (`validate_sealed_field`).
 */

/** HPKE suite: X25519 / HKDF-SHA256 / ChaCha20-Poly1305 (RFC 9180). */
export const ALG = "HPKE-v1-X25519-HKDF-SHA256-ChaCha20Poly1305";

export const SCHEMA_SEALED_FIELD_V1 = "defarm.sealed_field.v1";
export const SCHEMA_SEALED_AAD_V1 = "defarm.sealed_aad.v1";
export const SCHEMA_ENC_KEY_BINDING_V1 = "defarm.encryption_key_binding.v1";

/** Sealer signature suite: Ed25519 over the JCS (RFC 8785) of the whole envelope minus the signature itself. */
export const SEALER_SIG_ALG = "ed25519_jcs_v1";

/** HPKE `info` (domain separation). */
export const HPKE_INFO = new TextEncoder().encode("defarm.sealed_field.v1");

/** HKDF `info` deriving the commitment key from the DK. */
export const COMMIT_INFO = new TextEncoder().encode(
  "defarm.sealed_field.commitment.v1",
);

/** Sizes fixed by the suite — the server enforces exact equality (engines#533). */
export const DK_LEN = 32;
export const NONCE_LEN = 12;
export const HPKE_ENC_LEN = 32;
export const WRAPPED_DK_LEN = 48; // DK(32) + Poly1305 tag(16)
export const ED25519_SEED_LEN = 32;
export const ED25519_SIG_LEN = 64;
export const X25519_KEY_LEN = 32;
