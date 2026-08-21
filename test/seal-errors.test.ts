import { describe, expect, it } from "vitest";
import { DefarmClient, MemoryKeystore } from "../src/client.js";
import { NotSealableFieldError } from "../src/errors.js";

/**
 * Issue #18 (found live in the MCP E2E review): the server rejects a non-sealable field with
 * HTTP 400 `{code: "validation_error", message: "sealed field failed policy validation"}` —
 * and the old mapping matched three strings the server never says, so NotSealableFieldError
 * never fired in production (the sdk#1 blocker class: typed mechanism that never runs).
 *
 * The fixture below is the server's REAL response shape (message pinned to postgres.rs; the
 * code is the generic validation_error — engines#618 asks for a structured one).
 */
function gatewayRejectingSeal() {
  return (async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    const respond = (status: number, body: unknown) =>
      new Response(JSON.stringify(body), { status });
    if (url.endsWith("/auth/me")) return respond(200, { user_id: "u1", workspace_id: "ws-1" });
    if (method === "POST" && /workspace\/(signing|encryption)-keys$/.test(url)) {
      return respond(201, { ok: true });
    }
    if (method === "GET" && url.includes("/items/")) {
      return respond(200, { item: { id: "11111111-2222-3333-4444-555555555555" } });
    }
    if (method === "POST" && url.endsWith("/events")) {
      // Verbatim server behavior for a field whose field_protection is not sealable.
      return respond(400, {
        code: "validation_error",
        message: "sealed field failed policy validation",
      });
    }
    throw new Error(`unexpected call: ${method} ${url}`);
  }) as unknown as typeof fetch;
}

describe("seal() maps the server's real policy rejection (issue #18)", () => {
  it("400 'sealed field failed policy validation' → NotSealableFieldError naming the field", async () => {
    const c = new DefarmClient({
      gateway: "https://example.invalid",
      auth: { bearer: "tok" },
      keystore: new MemoryKeystore(),
      fetch: gatewayRejectingSeal(),
    });
    await expect(
      c.seal({ dfid: "DFID-X", fieldPath: "preco_venda", value: "R$ 8.500,00", circuitId: "c1" }),
    ).rejects.toThrow(NotSealableFieldError);
    await expect(
      c.seal({ dfid: "DFID-X", fieldPath: "preco_venda", value: "x", circuitId: "c1" }),
    ).rejects.toThrow(/preco_venda/);
  });
});
