import { hkdf } from "@noble/hashes/hkdf";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { COMMIT_INFO } from "./constants.js";
import { toHex } from "./encoding.js";

/**
 * Hiding commitment: `HMAC-SHA256(K, plaintext)` with `K = HKDF-SHA256(DK, info=commitment.v1)`.
 *
 * The HMAC key derives from the secret DK, so the server — which never sees the DK — cannot
 * brute-force low-entropy plaintexts (CPF, SISBOV, weight) from the commitment, even though the
 * commitment may be publicly anchored. The recipient, who unwraps the DK, recomputes and checks.
 * Two seals of the same plaintext get fresh DKs → different commitments → no correlation.
 * (Closes the engines#524 finding: a raw sha256(plaintext) of a CPF fell in 423s.)
 *
 * Rust reference: `hidden_commitment` in sealed_field.rs — HKDF salt is empty (None).
 */
export function hiddenCommitment(dk: Uint8Array, plaintext: Uint8Array): string {
  const commitKey = hkdf(sha256, dk, undefined, COMMIT_INFO, 32);
  return toHex(hmac(sha256, commitKey, plaintext));
}
