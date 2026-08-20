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

/** One sealed field addressed to the calling workspace (`GET /v1/workspace/sealed-fields`). */
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
  /** The Ed25519 public key the authorship was verified against — so the client can re-run it itself. */
  sealer_signing_pubkey_b64?: string | null;
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
