import { execFile } from "node:child_process";
import { symlink, mkdtemp } from "node:fs/promises";
import os from "node:os";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { formatSecurityCheckJson, formatSecurityCheckResult, isDirectCliExecution } from "../src/cli.js";

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = path.join(repoRoot, "src", "cli.ts");

describe("devguard CLI", () => {
  it("prints help", async () => {
    const { stdout } = await execFileAsync("node", ["--import", "tsx", cliPath, "--help"], {
      cwd: repoRoot,
    });

    expect(stdout).toContain("DevGuard");
    expect(stdout).toContain("使い方:");
    expect(stdout).toContain("doctor");
    expect(stdout).toContain("check --staged");
    expect(stdout).toContain("check --staged-diff");
    expect(stdout).toContain("check --worktree-diff");
    expect(stdout).toContain("check --all-diff");
    expect(stdout).toContain("push-check");
    expect(stdout).toContain("install-hooks [--include-submodules]");
  });

  it("detects direct execution through a symlinked bin path", async () => {
    const tempDir = await mkdtemp(path.join(os.tmpdir(), "devguard-cli-bin-"));
    const binPath = path.join(tempDir, "devguard");
    await symlink(cliPath, binPath);

    expect(isDirectCliExecution(new URL(`file://${cliPath}`).href, binPath)).toBe(true);
  });

  it("formats security results for humans and CI without sensitive previews", () => {
    const findings = [{
      id: "finding-1",
      ruleId: "secret-to-log",
      language: "typescript",
      severity: "high",
      confidence: "high",
      filePath: "src/auth.ts",
      lineNumber: 12,
      source: "environment",
      sink: "logger",
      flow: "environment -> logger",
      message: "環境変数がログへ流入する可能性があります。",
      remediation: "固定メッセージへ置き換えてください。",
    }] as const;

    expect(formatSecurityCheckResult([...findings])).toContain("secret-to-log");
    const json = JSON.parse(formatSecurityCheckJson([...findings]));
    expect(json.summary).toMatchObject({ total: 1, active: 1, high: 1, byRule: { "secret-to-log": 1 } });
    expect(json.findings[0]).not.toHaveProperty("preview");
  });
});
