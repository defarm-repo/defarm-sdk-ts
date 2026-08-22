import { execFile } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { beforeAll, describe, expect, it } from "vitest";

const run = promisify(execFile);

/**
 * THE WAY THE USER RUNS IT (P0 of the 0.2.0 release review): npm pack → clean-dir install →
 * execute `node_modules/.bin/defarm`, i.e. through the SYMLINK npm creates. The 0.2.0 bin was
 * published inert because every CLI test ran `node dist/cli.js` directly — the fourth instance
 * of this project's "the test walks a path the user never walks" family. This suite walks the
 * user's path, and only the user's path.
 */
let binPath: string;

beforeAll(async () => {
  const stage = mkdtempSync(join(tmpdir(), "defarm-bin-"));
  const { stdout } = await run("npm", ["pack", "--pack-destination", stage], {
    cwd: join(import.meta.dirname, ".."),
  });
  const tgz = join(stage, stdout.trim().split("\n").pop()!);
  const app = join(stage, "app");
  await run("npm", ["init", "-y"], { cwd: stage });
  await run("npm", ["install", tgz, "--prefix", app, "--no-audit", "--no-fund"], { cwd: stage });
  binPath = join(app, "node_modules", ".bin", "defarm");
}, 180_000);

describe("the installed bin (through npm's symlink)", { timeout: 30_000 }, () => {
  it("no args → usage on stderr, exit 1 — NOT a silent exit 0", async () => {
    const e = await run(binPath, []).catch((err) => err as { code: number; stderr: string; stdout: string });
    expect((e as { code: number }).code).toBe(1);
    expect((e as { stderr: string }).stderr).toContain("Commands:");
  });

  it("help → usage, exit 0", async () => {
    const { stderr } = await run(binPath, ["help"]);
    expect(stderr).toContain("defarm seal --dfid");
  });
});
