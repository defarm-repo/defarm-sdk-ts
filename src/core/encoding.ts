/** Standard base64 (with padding) and lowercase hex — same conventions as the Rust oracle. */

const B64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function toBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2]! : 0;
    out += B64_ALPHABET[a >> 2]! + B64_ALPHABET[((a & 3) << 4) | (b >> 4)]!;
    out += i + 1 < bytes.length ? B64_ALPHABET[((b & 15) << 2) | (c >> 6)]! : "=";
    out += i + 2 < bytes.length ? B64_ALPHABET[c & 63]! : "=";
  }
  return out;
}

export function fromBase64(s: string): Uint8Array {
  const trimmed = s.trim();
  if (typeof Buffer !== "undefined") {
    const buf = Buffer.from(trimmed, "base64");
    // Buffer silently ignores invalid characters; re-encode to detect garbage input.
    if (Buffer.from(buf).toString("base64").replace(/=+$/, "") !== trimmed.replace(/=+$/, "")) {
      throw new Error("invalid base64");
    }
    return new Uint8Array(buf);
  }
  const bin = atob(trimmed);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function fromUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}
