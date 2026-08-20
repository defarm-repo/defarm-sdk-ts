import type { SealedField } from "../core/envelope.js";

/** `GET /auth/me` — enough of it for the SDK's needs. */
export interface UserInfo {
  user_id?: string;
  id?: string;
  email?: string;
  workspace_id?: string;
  workspace?: { id?: string; name?: string };
  [k: string]: unknown;
}

/**
 * One sealed field addressed to the calling workspace (`GET /v1/workspace/sealed-fields`).
 *
 * Field names are PINNED to the Rust `RecipientSealedField` struct in
 * `engines .../item-registry/src/api/trust_encryption_keys.rs` — never invent or "improve" a
 * name here: a wrong name makes an optional check silently vanish instead of failing (that is
 * exactly how PR#1's blocker was born — the local authorship re-verification never ran because
 * this type guessed `sealer_signing_pubkey_b64` for what the server calls
 * `sealer_public_key_b64`). `test/api-shape.test.ts` guards this contract.
 */
export interface RecipientSealedField {
  dfid: string;
  event_id: string;
  event_type: string;
  occurred_at: string;
  field_path: string;
  content_type: string;
  /** Which of MY encryption keys this envelope was sealed to (which private key opens it). */
  recipient_enc_key_id: string;
  /** The whole envelope — the client opens it locally. The server is structurally blind. */
  sealed_field: SealedField;
  sealer_workspace_id: string;
  sealer_key_id: string;
  /** Server-side re-verification of the sealer signature against the trusted key valid at event time. */
  authorship_verified: boolean;
  /**
   * The Ed25519 public key the authorship was verified against — so the client can re-run the
   * verification itself instead of trusting the server's boolean. `null` = no key was valid at
   * event time.
   */
  sealer_public_key_b64?: string | null;
  commitment_alg?: string;
  commitment_value?: string;
  [k: string]: unknown;
}

export interface RecipientSealedFieldsPage {
  sealed_fields: RecipientSealedField[];
  /**
   * Keyset cursor. Loop-stop condition is `next_cursor == null`, NOT an empty page — a page can
   * come back empty WITH a cursor (engines#548).
   */
  next_cursor: string | null;
}
