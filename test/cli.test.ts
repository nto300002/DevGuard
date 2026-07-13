import { execFile } from "node:child_process";
import { symlink, mkdtemp } from "node:fs/promises";
import os from "node:os";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { isDirectCliExecution } from "../src/cli.js";

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
    expect(stdout).toContain("check --staged-diff");
    expect(stdout).toContain("check --worktree-diff");
    expect(stdout).toContain("check --all-diff");
    expect(stdout).toContain("push-check");
  });

  it("detects direct execution through a symlinked bin path", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "devguard-cli-bin-"));
    const binPath = path.join(tempDir, "devguard");
    await symlink(cliPath, binPath);

    expect(isDirectCliExecution(new URL(`file://${cliPath}`).href, binPath)).toBe(true);
  });
});
