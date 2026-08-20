import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { sha256 } from "@noble/hashes/sha256";
import { canonicalAad } from "./aad.js";
import { hiddenCommitment } from "./commitment.js";
import {
  ALG,
  DK_LEN,
  NONCE_LEN,
  SCHEMA_SEALED_FIELD_V1,
} from "./constants.js";
import { concatBytes, fromBase64, toBase64, toHex, utf8 } from "./encoding.js";
import type { Recipient, SealedField, Wrap } from "./envelope.js";
import { hpkeWrapDk } from "./hpke.js";

/**
 * Seal one field for N recipients. Pure crypto — no network, no storage. Mirrors `seal_field`
 * in sealed_field.rs step by step:
 *
 *   1 random DK  →  hiding commitment  →  canonical AAD  →  ciphertext = nonce || AEAD(DK, value)
 *   →  one HPKE wrap of the SAME DK per recipient (1 vault, N padlocks — not N vaults).
 *
 * The result carries an EMPTY sealer block: authorship is a separate step (`signSealedField`),
 * because the signing key (Ed25519) is distinct from the encryption keys and may be custodied.
 *
 * `eventId` here is the CLIENT event id (a nonce you pick, e.g. a UUID) — the server assigns the
 * real event id after the POST and links it.
 */
export async function sealField(
  dfid: string,
  eventId: string,
  fieldPath: string,
  contentType: string,
  plaintext: Uint8Array,
  recipients: Recipient[],
): Promise<SealedField> {
  const dk = crypto.getRandomValues(new Uint8Array(DK_LEN));

  const commitment = hiddenCommitment(dk, plaintext);
  const aad = canonicalAad(
    SCHEMA_SEALED_FIELD_V1,
    ALG,
    dfid,
    eventId,
    fieldPath,
    contentType,
    commitment,
  );
  const aadBytes = utf8(aad);

  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const ct = chacha20poly1305(dk, nonce, aadBytes).encrypt(plaintext);
  const ciphertext = concatBytes(nonce, ct);

  const wraps: Wrap[] = [];
  for (const r of recipients) {
    const pubBytes = fromBase64(r.encPubkeyB64);
    const { enc, wrappedDk } = await hpkeWrapDk(pubBytes, dk, aadBytes);
    wraps.push({
      recipient_workspace_id: r.workspaceId,
      recipient_enc_key_id: r.encKeyId,
      kid_fingerprint: `sha256:${toHex(sha256(pubBytes))}`,
      hpke_enc_b64: toBase64(enc),
      wrapped_dk_b64: toBase64(wrappedDk),
    });
  }

  return {
    schema: SCHEMA_SEALED_FIELD_V1,
    alg: ALG,
    dfid,
    event_id: eventId,
    field_path: fieldPath,
    content_type: contentType,
    aad,
    ciphertext_b64: toBase64(ciphertext),
    commitment_sha256: commitment,
    wraps,
    sealer_workspace_id: "",
    sealer_key_id: "",
    sealer_sig_alg: "",
    sealer_sig_b64: "",
  };
}
