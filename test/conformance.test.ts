import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  canonicalAad,
  canonicalEncKeyBinding,
  canonicalSealerSigningString,
  hiddenCommitment,
  fromBase64,
  openField,
  verifyEncKeyBinding,
  verifySealerSignature,
} from "../src/core/index.js";
import { localAuthorshipCheck } from "../src/client.js";
import type { RecipientSealedField } from "../src/api/types.js";
import type { SealedField } from "../src/core/envelope.js";

/**
 * Cross-language conformance vectors (engines#591). The Rust implementation is the ORACLE:
 * `item-registry/tests/ts_conformance_vector_gen.rs` generates `vectors/*.json` with fixed
 * inputs and the exact expected outputs. This suite replays them and demands byte equality.
 * NO language implementation ships to production without this green.
 *
 * FAIL CLOSED (issues #2 and #9): the guard counts ASSERTING SECTIONS, not files — an empty
 * directory, `[]`, or vectors with no known section must fail, never pass green.
 */
const VECTORS_DIR = join(dirname(fileURLToPath(import.meta.url)), "vectors");

interface ConformanceVector {
  name: string;
  /** Deterministic pieces: canonical strings + commitment, recomputable from inputs. */
  aad?: {
    dfid: string;
    event_id: string;
    field_path: string;
    content_type: string;
    commitment: string;
    expected: string;
  };
  commitment?: { dk_b64: string; plaintext_b64: string; expected_hex: string };
  binding?: {
    workspace_id: string;
    enc_key_id: string;
    enc_pubkey_b64: string;
    expected_canonical: string;
    sig_b64?: string;
    signing_pubkey_b64?: string;
  };
  /** A full envelope sealed by Rust: TS must open it (every listed recipient) and verify its signature. */
  envelope?: {
    sealed_field: SealedField;
    recipients: {
      enc_key_id: string;
      privkey_b64: string;
      expected_plaintext_b64: string;
    }[];
    sealer_signing_pubkey_b64: string;
    expected_signing_string: string;
  };
  /**
   * A `RecipientSealedField` serialized by the REAL Rust serializer (serde_json) — the SDK pins
   * the API response field names here, not in prose (the sdk-ts#1 blocker class).
   */
  api_response?: {
    recipient_sealed_field: RecipientSealedField;
    recipient_privkey_b64: string;
    expected_plaintext_b64: string;
    expected_local_authorship: boolean;
  };
}

/** Sections of a vector that actually assert something. */
const SECTIONS = ["aad", "commitment", "binding", "envelope", "api_response"] as const;

const files = existsSync(VECTORS_DIR)
  ? readdirSync(VECTORS_DIR).filter((f) => f.endsWith(".json"))
  : [];

const fileVectors = files.map((file) => {
  const parsed = JSON.parse(readFileSync(join(VECTORS_DIR, file), "utf8"));
  if (!Array.isArray(parsed)) {
    throw new Error(`vector file ${file} must hold a JSON array of vectors`);
  }
  return { file, vectors: parsed as ConformanceVector[] };
});

const totalChecks = fileVectors.reduce(
  (n, { vectors }) =>
    n + vectors.reduce((m, v) => m + SECTIONS.filter((s) => v[s] != null).length, 0),
  0,
);

describe("conformance vectors (Rust oracle, engines#591)", () => {
  it("at least one asserting vector section is present (the guard fails closed)", () => {
    expect(
      totalChecks,
      "test/vectors/ holds no asserting vectors — the anti-drift guard would be inert. " +
        "Restore the vectors or regenerate them from the Rust oracle (engines#591).",
    ).toBeGreaterThan(0);
  });

  for (const { file, vectors } of fileVectors) {
    for (const v of vectors) {
      describe(`${file} :: ${v.name}`, () => {
        if (v.aad) {
          it("canonical AAD matches byte-for-byte", () => {
            const a = v.aad!;
            expect(
              canonicalAad(
                "defarm.sealed_field.v1",
                "HPKE-v1-X25519-HKDF-SHA256-ChaCha20Poly1305",
                a.dfid,
                a.event_id,
                a.field_path,
                a.content_type,
                a.commitment,
              ),
            ).toBe(a.expected);
          });
        }
        if (v.commitment) {
          it("hidden commitment matches", () => {
            const c = v.commitment!;
            expect(
              hiddenCommitment(fromBase64(c.dk_b64), fromBase64(c.plaintext_b64)),
            ).toBe(c.expected_hex);
          });
        }
        if (v.binding) {
          it("canonical binding matches; signature verifies", () => {
            const b = v.binding!;
            expect(
              canonicalEncKeyBinding(b.workspace_id, b.enc_key_id, b.enc_pubkey_b64),
            ).toBe(b.expected_canonical);
            if (b.sig_b64 && b.signing_pubkey_b64) {
              expect(
                verifyEncKeyBinding(
                  b.workspace_id,
                  b.enc_key_id,
                  b.enc_pubkey_b64,
                  b.sig_b64,
                  b.signing_pubkey_b64,
                ),
              ).toBe(true);
            }
          });
        }
        if (v.envelope) {
          it("verifies the Rust-sealed envelope's signature and canonical string", () => {
            const e = v.envelope!;
            expect(canonicalSealerSigningString(e.sealed_field)).toBe(
              e.expected_signing_string,
            );
            expect(
              verifySealerSignature(e.sealed_field, e.sealer_signing_pubkey_b64),
            ).toBe(true);
          });
          it("every listed recipient opens to the exact plaintext", async () => {
            const e = v.envelope!;
            expect(e.recipients.length).toBeGreaterThan(0);
            for (const r of e.recipients) {
              const plaintext = await openField(
                e.sealed_field,
                r.enc_key_id,
                fromBase64(r.privkey_b64),
              );
              expect(plaintext).toEqual(fromBase64(r.expected_plaintext_b64));
            }
          });
        }
        if (v.api_response) {
          it("the serializer-shaped response drives local authorship + open (names pinned to the server)", async () => {
            const a = v.api_response!;
            const field = a.recipient_sealed_field;
            // The whole point: the field names here came from serde_json over the Rust struct.
            // If the SDK reads a wrong/invented name, this returns null and the test fails.
            expect(localAuthorshipCheck(field)).toBe(a.expected_local_authorship);
            const plaintext = await openField(
              field.sealed_field,
              field.recipient_enc_key_id,
              fromBase64(a.recipient_privkey_b64),
            );
            expect(plaintext).toEqual(fromBase64(a.expected_plaintext_b64));
          });
        }
      });
    }
  }
});
