import { execFile } from "node:child_process";
import { symlink, mkdtemp } from "node:fs/promises";
import os from "node:os";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { formatSecurityCheckJson, formatSecurityCheckResult, formatSecurityCheckSarif, isDirectCliExecution } from "../src/cli.js";

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

  it("formats Security Flow and General Vulnerability findings as SARIF", () => {
    const findings = [
      {
        id: "flow-1", ruleId: "secret-to-log", language: "typescript", severity: "high", confidence: "high",
        filePath: "src/auth.ts", lineNumber: 12, source: "environment", sink: "logger", flow: "environment -> logger",
        message: "環境変数がログへ流入する可能性があります。", remediation: "固定メッセージへ置き換えてください。", category: "security-flow",
      },
      {
        id: "general-1", ruleId: "general-sqli", language: "python", severity: "high", confidence: "medium",
        filePath: "app/users.py", lineNumber: 21, source: "user-input", sink: "sql", flow: "external input -> sql",
        message: "動的なSQL文字列を実行している可能性があります。", remediation: "parameterized queryを使用してください。", category: "general-vulnerability",
        cwe: "CWE-89", owaspCategory: "A03:2021-Injection",
      },
    ] as const;
    const sarif = JSON.parse(formatSecurityCheckSarif([...findings], [{ filePath: "src/broken.ts", language: "typescript", kind: "parse-error", message: "構文を解析できません。" }]));

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-2.1.0");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe("DevGuard");
    expect(sarif.runs[0].results).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: "secret-to-log", level: "error", properties: expect.objectContaining({ category: "security-flow", confidence: "high" }) }),
      expect.objectContaining({ ruleId: "general-sqli", properties: expect.objectContaining({ category: "general-vulnerability", cwe: "CWE-89", owaspCategory: "A03:2021-Injection" }) }),
    ]));
    expect(sarif.runs[0].invocations[0].toolExecutionNotifications).toEqual([
      expect.objectContaining({ level: "error", message: { text: "構文を解析できません。" } }),
    ]);
    expect(formatSecurityCheckSarif([...findings], [])).not.toContain("real-secret-value");
  });
});
