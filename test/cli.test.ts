import { execFile } from "node:child_process";
import { readFile, symlink, mkdtemp } from "node:fs/promises";
import os from "node:os";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { formatSecurityCheckJson, formatSecurityCheckResult, formatSecurityCheckSarif, isDirectCliExecution } from "../src/cli.js";

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = path.join(repoRoot, "src", "cli.ts");
const tsxBin = path.join(repoRoot, "node_modules", ".bin", "tsx");

describe("devguard CLI", () => {
  it("prints help", async () => {
    const { stdout } = await execFileAsync("node", ["--import", "tsx", cliPath, "--help"], {
      cwd: repoRoot,
    });

    expect(stdout).toContain("SafeCheck");
    expect(stdout).toContain("使い方:");
    expect(stdout).toContain("doctor");
    expect(stdout).toContain("check --staged");
    expect(stdout).toContain("check --staged-diff");
    expect(stdout).toContain("check --worktree-diff");
    expect(stdout).toContain("check --all-diff");
    expect(stdout).toContain("push-check");
    expect(stdout).toContain("install-hooks [--include-submodules]");
    expect(stdout).toContain("<command> --save-log [path]");
  });

  it("saves the terminal output as Markdown without changing the command result", async () => {
    const repo = await mkdtemp(path.join(os.tmpdir(), "devguard-cli-log-"));
    await execFileAsync("git", ["init", "-b", "main"], { cwd: repo });
    const logPath = path.join(repo, ".safecheck", "logs", "doctor.md");

    const { stdout } = await execFileAsync(tsxBin, [cliPath, "doctor", "--save-log", logPath], { cwd: repo });
    const markdown = await readFile(logPath, "utf8");

    expect(stdout).toContain("SafeCheck doctor");
    expect(markdown).toContain("# SafeCheck 実行ログ");
    expect(markdown).toContain("safecheck doctor");
    expect(markdown).toContain("SafeCheck doctor");
    expect(markdown).toContain("終了コード: `0`");
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

  it("prints contextual labels for findings", () => {
    const findings = [{
      id: "finding-1",
      ruleId: "secret-to-deployment",
      language: "yaml",
      severity: "medium",
      confidence: "low",
      filePath: ".github/workflows/cd-backend.yml",
      lineNumber: 100,
      source: "secret",
      sink: "deployment",
      flow: "Secret -> deployment configuration",
      message: "CIテスト用Secret参照です。",
      remediation: "用途と期限を確認してください。",
      labels: ["CIテスト用途", "過剰検出の疑い"],
    }] as const;

    expect(formatSecurityCheckResult([...findings])).toContain("ラベル: CIテスト用途, 過剰検出の疑い");
    expect(JSON.parse(formatSecurityCheckJson([...findings])).findings[0].labels).toEqual(["CIテスト用途", "過剰検出の疑い"]);
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
    expect(sarif.runs[0].tool.driver.name).toBe("SafeCheck");
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
