import { describe, expect, it } from "vitest";
import { DefarmClient, MemoryKeystore } from "../src/client.js";
import { KeyMismatchError } from "../src/errors.js";

/**
 * Issue #4: a 409 on key registration is only success when the key registered under that key_id
 * matches the public key the LOCAL private key derives. A mismatch (restored backup, two machines
 * sharing an id, a race) must be a hard, named error — silently continuing makes every seal
 * addressed to this workspace unopenable, with the failure surfacing far from the cause.
 */

/** Fake gateway: /auth/me + key registration returning 409, with a configurable GET listing. */
function fakeGateway(behavior: { listedPubkey: "echo" | "different" | "absent" }) {
  let lastPostedSigning: { key_id: string; public_key_b64: string } | null = null;
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    const respond = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status });

    if (url.endsWith("/auth/me")) {
      return respond(200, { user_id: "u1", workspace_id: "ws-1" });
    }
    if (url.endsWith("/workspace/signing-keys") && method === "POST") {
      lastPostedSigning = JSON.parse(init!.body as string);
      return respond(409, { code: "key_exists", message: "already registered" });
    }
    if (url.endsWith("/workspace/signing-keys") && method === "GET") {
      if (behavior.listedPubkey === "absent") return respond(200, []);
      const pub =
        behavior.listedPubkey === "echo"
          ? lastPostedSigning!.public_key_b64
          : "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
      return respond(200, [{ key_id: lastPostedSigning!.key_id, public_key_b64: pub }]);
    }
    if (url.endsWith("/workspace/encryption-keys") && method === "POST") {
      return respond(201, { ok: true });
    }
    throw new Error(`unexpected call: ${method} ${url}`);
  }) as unknown as typeof fetch;
  return fetchImpl;
}

function client(fetchImpl: typeof fetch): DefarmClient {
  return new DefarmClient({
    gateway: "https://example.invalid",
    auth: { bearer: "tok" },
    keystore: new MemoryKeystore(),
    fetch: fetchImpl,
  });
}

describe("ensureKeys treats 409 as success ONLY on matching public key (issue #4)", () => {
  it("409 + same public key registered → idempotent success", async () => {
    const c = client(fakeGateway({ listedPubkey: "echo" }));
    const id = await c.ensureKeys();
    expect(id.workspaceId).toBe("ws-1");
  });

  it("409 + DIFFERENT public key under the same key_id → hard KeyMismatchError", async () => {
    const c = client(fakeGateway({ listedPubkey: "different" }));
    await expect(c.ensureKeys()).rejects.toThrow(KeyMismatchError);
  });

  it("409 but the key_id is not in the listing → the original 409 surfaces", async () => {
    const c = client(fakeGateway({ listedPubkey: "absent" }));
    await expect(c.ensureKeys()).rejects.toThrow(/409|already registered/);
  });
});
