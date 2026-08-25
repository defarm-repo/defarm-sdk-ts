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

describe("seal() event_type reaches the wire (defarm-main gap: policy is keyed by event type)", () => {
  function capturingGateway() {
    const posted: Record<string, unknown>[] = [];
    const fetchImpl = (async (url: string, init?: RequestInit) => {
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
        posted.push(JSON.parse(init!.body as string));
        return respond(201, { ok: true });
      }
      throw new Error(`unexpected call: ${method} ${url}`);
    }) as unknown as typeof fetch;
    return { fetchImpl, posted };
  }

  function clientWith(fetchImpl: typeof fetch) {
    return new DefarmClient({
      gateway: "https://example.invalid",
      auth: { bearer: "tok" },
      keystore: new MemoryKeystore(),
      fetch: fetchImpl,
    });
  }

  it("defaults stay item_updated / producer (backwards compatible)", async () => {
    const { fetchImpl, posted } = capturingGateway();
    await clientWith(fetchImpl).seal({ dfid: "DFID-X", fieldPath: "preco_venda", value: "x", circuitId: "c1" });
    expect(posted[0]!.event_type).toBe("item_updated");
    expect(posted[0]!.source_type).toBe("producer");
  });

  it("sourceType: 'certifier' lands verbatim (HU-21: the audit trail names the right actor)", async () => {
    const { fetchImpl, posted } = capturingGateway();
    await clientWith(fetchImpl).seal({
      dfid: "DFID-X", fieldPath: "veredito", value: "conforme", circuitId: "c1",
      eventType: "attestation_issued", sourceType: "certifier",
    });
    expect(posted[0]!.event_type).toBe("attestation_issued");
    expect(posted[0]!.source_type).toBe("certifier");
  });

  it("eventType: 'item_terminated' lands verbatim in the POSTed event", async () => {
    const { fetchImpl, posted } = capturingGateway();
    await clientWith(fetchImpl).seal({
      dfid: "DFID-X",
      fieldPath: "motivo_baixa",
      value: "Furto",
      circuitId: "c1",
      eventType: "item_terminated",
    });
    expect(posted[0]!.event_type).toBe("item_terminated");
    expect(posted[0]!.source_type).toBe("producer"); // default intacto
    // The client event id inside the envelope must match the payload's (AAD binding intact).
    const payload = posted[0]!.payload as { client_event_id: string; $sealed: { sealed_field: { event_id: string } }[] };
    expect(payload.$sealed[0]!.sealed_field.event_id).toBe(payload.client_event_id);
  });
});
