import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { canonicalAad } from "./aad.js";
import { hiddenCommitment } from "./commitment.js";
import { NONCE_LEN } from "./constants.js";
import { fromBase64, utf8 } from "./encoding.js";
import type { SealedField } from "./envelope.js";
import { hpkeUnwrapDk } from "./hpke.js";

export type OpenFailureReason =
  | "no_wrap_for_recipient"
  | "encoding"
  | "aad_mismatch"
  | "hpke_open"
  | "aead_open"
  | "commitment_mismatch";

export class OpenFieldError extends Error {
  constructor(public readonly reason: OpenFailureReason) {
    super(`open failed: ${reason}`);
    this.name = "OpenFieldError";
  }
}

/**
 * A recipient opens the envelope with their X25519 private key. The server cannot run this — it
 * has no private key. Mirrors `open_field` in sealed_field.rs, including its two integrity gates:
 *
 * - the AAD is RE-DERIVED from the struct fields and must equal the stored one (anti-frankenstein:
 *   swapping dfid/event/field/content_type/alg/schema makes the open fail);
 * - the plaintext must match the hiding commitment recomputed with the DK.
 */
export async function openField(
  sealed: SealedField,
  encKeyId: string,
  myPrivkey: Uint8Array,
): Promise<Uint8Array> {
  const wrap = sealed.wraps.find((w) => w.recipient_enc_key_id === encKeyId);
  if (!wrap) throw new OpenFieldError("no_wrap_for_recipient");

  const expectedAad = canonicalAad(
    sealed.schema,
    sealed.alg,
    sealed.dfid,
    sealed.event_id,
    sealed.field_path,
    sealed.content_type,
    sealed.commitment_sha256,
  );
  if (expectedAad !== sealed.aad) throw new OpenFieldError("aad_mismatch");
  const aadBytes = utf8(expectedAad);

  let enc: Uint8Array, wrappedDk: Uint8Array, ctAll: Uint8Array;
  try {
    enc = fromBase64(wrap.hpke_enc_b64);
    wrappedDk = fromBase64(wrap.wrapped_dk_b64);
    ctAll = fromBase64(sealed.ciphertext_b64);
  } catch {
    throw new OpenFieldError("encoding");
  }

  let dk: Uint8Array;
  try {
    dk = await hpkeUnwrapDk(myPrivkey, enc, wrappedDk, aadBytes);
  } catch {
    throw new OpenFieldError("hpke_open");
  }

  if (ctAll.length < NONCE_LEN) throw new OpenFieldError("aead_open");
  const nonce = ctAll.slice(0, NONCE_LEN);
  const ct = ctAll.slice(NONCE_LEN);
  let plaintext: Uint8Array;
  try {
    plaintext = chacha20poly1305(dk, nonce, aadBytes).decrypt(ct);
  } catch {
    throw new OpenFieldError("aead_open");
  }

  if (hiddenCommitment(dk, plaintext) !== sealed.commitment_sha256) {
    throw new OpenFieldError("commitment_mismatch");
  }
  return plaintext;
}
