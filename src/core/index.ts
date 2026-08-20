/**
 * @defarm/sdk core — the pure crypto of the sealed envelope (blind envelope, N2).
 *
 * Everything in this module is side-effect free: no network, no filesystem, no globals beyond
 * WebCrypto's `crypto.getRandomValues`. This is the auditable surface: an agency reviewing the
 * client cryptography reads this directory and the conformance vectors, nothing else.
 *
 * Byte-for-byte compatibility with the Rust reference implementation
 * (`engines .../item-registry/src/api/sealed_field.rs`) is enforced by the cross-language
 * conformance vectors (engines#591). No release ships without them green.
 */
export * from "./constants.js";
export * from "./encoding.js";
export { jcsSerialize } from "./jcs.js";
export type { SealedField, Wrap, Recipient } from "./envelope.js";
export { canonicalAad } from "./aad.js";
export { hiddenCommitment } from "./commitment.js";
export {
  generateX25519KeyPair,
  x25519PublicKey,
  hpkeWrapDk,
  hpkeUnwrapDk,
  validateRecipientPubkey,
} from "./hpke.js";
export {
  generateEd25519KeyPair,
  ed25519PublicKey,
  canonicalSealerSigningString,
  signSealedField,
  verifySealerSignature,
  canonicalEncKeyBinding,
  signEncKeyBinding,
  verifyEncKeyBinding,
} from "./signing.js";
export { sealField } from "./seal.js";
export { openField, OpenFieldError, type OpenFailureReason } from "./open.js";
