import { execFile } from "node:child_process";
import { createServer, type Server } from "node:http";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const run = promisify(execFile);

/**
 * The CLI's contract (engines#590): JSON on stdout, hints/errors on stderr, honest exit codes,
 * and the same security posture as the MCP server — credentials come from the ENVIRONMENT only
 * (argv leaks into shell history and process listings; parseArgs strict rejects unknown flags,
 * so `--password` is not even parseable).
 */
function cli(args: string[], env: Record<string, string> = {}) {
  return run("npx", ["tsx", "src/cli.ts", ...args], {
    env: { ...process.env, DEFARM_GATEWAY: "", DEFARM_EMAIL: "", DEFARM_PASSWORD: "", DEFARM_API_KEY: "", ...env },
  });
}

let server: Server;
let gateway: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    res.setHeader("content-type", "application/json");
    if (req.url?.startsWith("/v1/verify/")) {
      res.end(JSON.stringify({ dfid: "DFID-X", trusted_timestamps: [{ authority: "freetsa" }] }));
    } else if (req.url === "/v1/items/DFID-X/public") {
      res.end(JSON.stringify({ item: { dfid: "DFID-X", sisbov_commitment: "a".repeat(64) } }));
    } else {
      res.statusCode = 404;
      res.end(JSON.stringify({ code: "not_found", message: "Item not found" }));
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  gateway = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
});

afterAll(() => new Promise<void>((r) => server.close(() => r())));

// Each case spawns a tsx subprocess (~seconds under a loaded runner) — generous timeout.
describe("defarm CLI", { timeout: 30_000 }, () => {
  it("no command → usage on stderr, exit 1", async () => {
    const e = await cli([]).catch((err) => err as { code: number; stderr: string });
    expect(e.code).toBe(1);
    expect(e.stderr).toContain("Commands:");
  });

  it("help → usage, exit 0", async () => {
    const { stderr } = await cli(["help"]);
    expect(stderr).toContain("defarm seal --dfid");
  });

  it("fails fast without DEFARM_GATEWAY, naming it", async () => {
    const e = await cli(["verify", "--dfid", "DFID-X"]).catch((err) => err as { code: number; stderr: string });
    expect(e.code).toBe(1);
    expect(e.stderr).toContain("DEFARM_GATEWAY");
  });

  it("credentials are NOT accepted via argv (posture: env only)", async () => {
    const e = await cli(["whoami", "--password", "hunter2"], { DEFARM_GATEWAY: "http://x" }).catch(
      (err) => err as { code: number; stderr: string },
    );
    expect(e.code).toBe(1);
    expect(e.stderr).toMatch(/Unknown option|password/i);
  });

  it("verify: JSON on stdout against a real HTTP gateway, exit 0", async () => {
    const { stdout } = await cli(["verify", "--dfid", "DFID-X"], { DEFARM_GATEWAY: gateway });
    const report = JSON.parse(stdout);
    expect(report.dfid).toBe("DFID-X");
    expect(report.hasTrustedTimestamps).toBe(true);
  });

  it("item --public: works without credentials; JSON is pipe-clean", async () => {
    const { stdout } = await cli(["item", "--dfid", "DFID-X", "--public"], {
      DEFARM_GATEWAY: gateway,
    });
    expect(JSON.parse(stdout).item.dfid).toBe("DFID-X");
  });

  it("authenticated command without creds → exit 1 naming the env vars", async () => {
    const e = await cli(["whoami"], { DEFARM_GATEWAY: gateway }).catch(
      (err) => err as { code: number; stderr: string },
    );
    expect(e.code).toBe(1);
    expect(e.stderr).toContain("DEFARM_EMAIL");
  });

  it("a malformed --to bundle blames the FILE, never the crypto (review finding on #22)", async () => {
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const dir = mkdtempSync(join(tmpdir(), "defarm-cli-"));
    const bad = join(dir, "not-a-bundle.json");
    writeFileSync(bad, JSON.stringify({ foo: "bar" }));
    const e = await cli(
      ["seal", "--dfid", "D", "--field", "f", "--value", "v", "--circuit", "c", "--to", bad],
      { DEFARM_GATEWAY: gateway, DEFARM_EMAIL: "a@b.c", DEFARM_PASSWORD: "x" },
    ).catch((err) => err as { code: number; stderr: string });
    expect(e.code).toBe(1);
    expect(e.stderr).toContain("not a recipient bundle");
    expect(e.stderr).toContain("missing field(s): workspaceId");
    expect(e.stderr).not.toContain("RecipientBindingError");
  });

  it("uniform 404 surfaces as exit 1 with the server's message — never a silent success", async () => {
    const e = await cli(["item", "--dfid", "DFID-PRIVATE", "--public"], {
      DEFARM_GATEWAY: gateway,
    }).catch((err) => err as { code: number; stderr: string });
    expect(e.code).toBe(1);
    expect(e.stderr).toContain("Item not found");
  });
});
