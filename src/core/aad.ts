import { SCHEMA_SEALED_AAD_V1 } from "./constants.js";
import { jcsSerialize } from "./jcs.js";

/**
 * Canonical AAD (JCS, RFC 8785) — the anti-frankenstein binding. Every contextual field of the
 * envelope goes in here, so on open the AAD is re-derived from the struct fields and compared:
 * swap any of them and decryption fails. Mirrors `canonical_aad` in sealed_field.rs.
 */
export function canonicalAad(
  fieldSchema: string,
  alg: string,
  dfid: string,
  eventId: string,
  fieldPath: string,
  contentType: string,
  commitment: string,
): string {
  return jcsSerialize({
    schema: SCHEMA_SEALED_AAD_V1,
    field_schema: fieldSchema,
    alg,
    dfid,
    event_id: eventId,
    field_path: fieldPath,
    content_type: contentType,
    commitment,
  });
}
