/**
 * JSON Canonicalization Scheme (RFC 8785) serializer.
 *
 * Vendored on purpose (~60 lines) instead of pulled as a dependency: this function decides the
 * exact bytes that get signed, so it must be trivially auditable. It must produce the same output
 * as `serde_jcs` on the Rust side — the conformance vectors (engines#591) are the guard.
 *
 * RFC 8785 in short: object keys sorted by UTF-16 code units, no whitespace, strings escaped as
 * ECMAScript `JSON.stringify`, numbers serialized as ECMAScript (shortest round-trip form).
 * `JSON.stringify` already implements the string/number rules; what it does not do is sort keys.
 */
export function jcsSerialize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new Error("JCS: non-finite numbers are not representable");
    }
    if (value === undefined) {
      throw new Error("JCS: undefined is not representable");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    // Arrays keep their order — JCS does NOT reorder arrays (which is why the
    // sealer signing string sorts wraps explicitly before serializing).
    return "[" + value.map((v) => jcsSerialize(v)).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  // Default JS string sort compares UTF-16 code units — exactly RFC 8785 §3.2.3.
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  const parts = keys.map((k) => JSON.stringify(k) + ":" + jcsSerialize(obj[k]));
  return "{" + parts.join(",") + "}";
}
