/**
 * Wire types of the sealed envelope — field names and encodings must match the Rust
 * `SealedField` / `Wrap` structs (`sealed_field.rs`). The server stores exactly this,
 * and stores no key: holding ciphertext + wraps + commitment, it structurally cannot read.
 */

/** The data key (DK) wrapped via HPKE for ONE recipient. Only their private key unwraps it. */
export interface Wrap {
  recipient_workspace_id: string;
  recipient_enc_key_id: string;
  /** `sha256:<hex>` of the recipient's public key (so they can confirm it is their lock). */
  kid_fingerprint: string;
  /** The HPKE encapsulated key (`enc`), base64 — 32 bytes for X25519. */
  hpke_enc_b64: string;
  /** The wrapped DK (HPKE ciphertext), base64 — 48 bytes (DK 32 + tag 16). */
  wrapped_dk_b64: string;
}

/** The sealed envelope the server stores — no plaintext, no key. */
export interface SealedField {
  schema: string;
  alg: string;
  dfid: string;
  /**
   * On the wire this carries the CLIENT event id (a nonce the sealer picks); the real event id is
   * server-assigned after the POST and linked server-side. It is bound into the AAD.
   */
  event_id: string;
  field_path: string;
  /** Declared content type of the sealed value (e.g. `text/plain`) — bound into the AAD. */
  content_type: string;
  /**
   * The canonical (JCS) AAD binding ciphertext to schema/alg/dfid/event/field/content_type/
   * commitment. Re-derived and compared on open — none of those fields is decorative.
   */
  aad: string;
  /** `nonce(12) || ciphertext`, base64. */
  ciphertext_b64: string;
  /** Hiding commitment `HMAC-SHA256(HKDF(DK), plaintext)`, lowercase hex — brute-force-proof without the DK. */
  commitment_sha256: string;
  wraps: Wrap[];
  /** Authorship: the workspace that ASSUMES the sealing (may differ from the submitter in mode A2). */
  sealer_workspace_id: string;
  /** Which of that workspace's registered signing keys (`trust_signing_keys.key_id`) signed. */
  sealer_key_id: string;
  /** Signature suite (`ed25519_jcs_v1`). Inside the signed material (anti protocol-ambiguity). */
  sealer_sig_alg: string;
  /** Ed25519 (base64) over the canonical signing string. The ONLY field outside the signed material. */
  sealer_sig_b64: string;
}

/** A recipient to seal to (public material only — the SDK never touches their private key). */
export interface Recipient {
  workspaceId: string;
  encKeyId: string;
  /** X25519 public key (32 bytes), base64. */
  encPubkeyB64: string;
}
