import { describe, expect, it } from "vitest";
import { localAuthorshipCheck } from "../src/client.js";
import type { RecipientSealedField } from "../src/api/types.js";
import {
  generateEd25519KeyPair,
  generateX25519KeyPair,
  sealField,
  signSealedField,
  toBase64,
  utf8,
} from "../src/core/index.js";

/**
 * Guard of the PR#1 blocker (Hetzner review): the SDK typed the sealer's public key under an
 * INVENTED name (`sealer_signing_pubkey_b64`), the server sends `sealer_public_key_b64`, and the
 * local authorship re-verification silently never ran — the integrator was left trusting the
 * server's `authorship_verified` boolean, exactly what the architecture exists to avoid.
 *
 * The fixture below is shaped with the server's EXACT field names, copied from the Rust struct
 * `RecipientSealedField` (trust_encryption_keys.rs) — the vector's mutation: if the client ever
 * reads a wrong/invented name again, `localAuthorshipCheck` returns null and this suite fails.
 */
async function serverShapedFixture() {
  const recipient = generateX25519KeyPair();
  const sealer = generateEd25519KeyPair();
  const unsigned = await sealField(
    "DFID-DEFARM-BR-2026-000002-000002",
    "22222222-3333-4444-5555-666666666666",
    "preco_venda",
    "text/plain",
    utf8("R$ 8.500,00"),
    [{ workspaceId: "ws-frigo", encKeyId: "enc-frigo", encPubkeyB64: toBase64(recipient.publicKey) }],
  );
  const envelope = signSealedField(unsigned, "ws-produtor", "sign-produtor", sealer.seed);

  // Field names below are verbatim from the Rust serializer — do not rename.
  const field: RecipientSealedField = {
    dfid: envelope.dfid,
    event_id: "0a0a0a0a-0b0b-0c0c-0d0d-0e0e0e0e0e0e",
    event_type: "item_updated",
    occurred_at: "2026-08-20T12:00:00Z",
    field_path: envelope.field_path,
    content_type: envelope.content_type,
    recipient_enc_key_id: "enc-frigo",
    sealed_field: envelope,
    sealer_workspace_id: envelope.sealer_workspace_id,
    sealer_key_id: envelope.sealer_key_id,
    authorship_verified: true,
    sealer_public_key_b64: toBase64(sealer.publicKey),
    commitment_alg: "hmac-sha256/hkdf-sha256",
    commitment_value: envelope.commitment_sha256,
  };
  return { field, sealer };
}

describe("API shape: local authorship re-verification actually runs", () => {
  it("a server-shaped response yields true — never a silent null", async () => {
    const { field } = await serverShapedFixture();
    expect(localAuthorshipCheck(field)).toBe(true);
  });

  it("a wrong sealer key yields false (the check bites, not just runs)", async () => {
    const { field } = await serverShapedFixture();
    const other = generateEd25519KeyPair();
    expect(
      localAuthorshipCheck({ ...field, sealer_public_key_b64: toBase64(other.publicKey) }),
    ).toBe(false);
  });

  it("null is reserved for the server sending no key (none valid at event time)", async () => {
    const { field } = await serverShapedFixture();
    expect(localAuthorshipCheck({ ...field, sealer_public_key_b64: null })).toBe(null);
  });

  it("regression: the invented field name alone must NOT satisfy the check", async () => {
    const { field, sealer } = await serverShapedFixture();
    // A response carrying the key ONLY under the old invented name = server never sent it.
    const wrongShape = {
      ...field,
      sealer_public_key_b64: null,
      sealer_signing_pubkey_b64: toBase64(sealer.publicKey),
    } as RecipientSealedField;
    expect(localAuthorshipCheck(wrongShape)).toBe(null);
  });
});
