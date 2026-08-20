import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { x25519 } from "@noble/curves/ed25519";
import { HPKE_INFO, X25519_KEY_LEN } from "./constants.js";

/** The one and only suite (RFC 9180): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305. */
const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  // Copy into a fresh ArrayBuffer — hpke-js requires ArrayBuffer, and slicing avoids
  // accidentally handing over a larger backing buffer.
  return bytes.slice().buffer;
}

/** Generate a fresh X25519 key pair. The private key never leaves the caller's side. */
export function generateX25519KeyPair(): {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
} {
  const privateKey = crypto.getRandomValues(new Uint8Array(X25519_KEY_LEN));
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/** Derive the X25519 public key from a private key (e.g. loaded from a keystore). */
export function x25519PublicKey(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey);
}

/**
 * Wrap the DK for one recipient: HPKE single-shot seal (Base mode) with the domain-separation
 * info and the envelope AAD. Mirrors the wrap step of `seal_field` in sealed_field.rs.
 */
export async function hpkeWrapDk(
  recipientPubkey: Uint8Array,
  dk: Uint8Array,
  aad: Uint8Array,
): Promise<{ enc: Uint8Array; wrappedDk: Uint8Array }> {
  const pk = await suite.kem.deserializePublicKey(toArrayBuffer(recipientPubkey));
  const sender = await suite.createSenderContext({
    recipientPublicKey: pk,
    info: toArrayBuffer(HPKE_INFO),
  });
  const wrapped = await sender.seal(toArrayBuffer(dk), toArrayBuffer(aad));
  return {
    enc: new Uint8Array(sender.enc),
    wrappedDk: new Uint8Array(wrapped),
  };
}

/**
 * Unwrap the DK with the recipient's private key. Fails if the key is not the addressee's
 * or the AAD diverges. Mirrors the HPKE step of `open_field`.
 */
export async function hpkeUnwrapDk(
  recipientPrivkey: Uint8Array,
  enc: Uint8Array,
  wrappedDk: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const sk = await suite.kem.deserializePrivateKey(toArrayBuffer(recipientPrivkey));
  const recipient = await suite.createRecipientContext({
    recipientKey: sk,
    enc: toArrayBuffer(enc),
    info: toArrayBuffer(HPKE_INFO),
  });
  const dk = await recipient.open(toArrayBuffer(wrappedDk), toArrayBuffer(aad));
  return new Uint8Array(dk);
}

/**
 * Reject at the door an X25519 public key HPKE could never seal to (low-order points, including
 * all-zeros). Same rule as sealing for real — a key that passes is sealable; one that fails would
 * register fine and then break EVERY later seal, far from the cause (engines#528).
 */
export async function validateRecipientPubkey(
  recipientPubkey: Uint8Array,
): Promise<boolean> {
  try {
    await hpkeWrapDk(recipientPubkey, new Uint8Array(0), new Uint8Array(0));
    return true;
  } catch {
    return false;
  }
}
