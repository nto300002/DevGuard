import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = path.join(repoRoot, "src", "cli.ts");

describe("devguard CLI", () => {
  it("prints help", async () => {
    const { stdout } = await execFileAsync("node", ["--import", "tsx", cliPath, "--help"], {
      cwd: repoRoot,
    });

    expect(stdout).toContain("DevGuard");
    expect(stdout).toContain("Usage:");
    expect(stdout).toContain("doctor");
    expect(stdout).toContain("check --staged");
    expect(stdout).toContain("push-check");
  });
});
