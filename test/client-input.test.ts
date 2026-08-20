import { describe, expect, it } from "vitest";
import { DefarmClient, MemoryKeystore } from "../src/client.js";
import { InvalidInputError } from "../src/errors.js";

/**
 * Issue #3: seal() and open() take the same object shape, and a missing field fails AT THE DOOR
 * with the field's name — an untyped caller (plain JS, tsx, an MCP agent) must never end up with
 * a 404 whose message prints the literal string "undefined".
 */
function offlineClient(): DefarmClient {
  return new DefarmClient({
    gateway: "https://example.invalid",
    keystore: new MemoryKeystore(),
    fetch: (() => {
      throw new Error("network must not be reached on input validation failures");
    }) as unknown as typeof fetch,
  });
}

describe("input validation fails at the door (issue #3)", () => {
  it("seal() names each missing field", async () => {
    const c = offlineClient();
    await expect(
      c.seal({ fieldPath: "preco_venda", value: "x", circuitId: "c" } as never),
    ).rejects.toThrow(/dfid/);
    await expect(
      c.seal({ dfid: "DFID-X", value: "x", circuitId: "c" } as never),
    ).rejects.toThrow(/fieldPath/);
    await expect(
      c.seal({ dfid: "DFID-X", fieldPath: "f", value: "x" } as never),
    ).rejects.toThrow(/circuitId/);
    await expect(
      c.seal({ dfid: "DFID-X", fieldPath: "f", circuitId: "c" } as never),
    ).rejects.toThrow(/value/);
  });

  it("open() names each missing field and rejects the old positional call shape", async () => {
    const c = offlineClient();
    await expect(c.open({ fieldPath: "f" } as never)).rejects.toThrow(/dfid/);
    await expect(c.open({ dfid: "DFID-X" } as never)).rejects.toThrow(/fieldPath/);
    // The pre-#3 positional habit — open("DFID-X", "campo") — must fail loudly, not print "undefined".
    await expect(
      (c.open as unknown as (a: string, b: string) => Promise<unknown>)("DFID-X", "campo"),
    ).rejects.toThrow(InvalidInputError);
  });

  it("empty strings are as invalid as missing fields", async () => {
    const c = offlineClient();
    await expect(c.open({ dfid: "", fieldPath: "f" })).rejects.toThrow(/dfid/);
  });
});
