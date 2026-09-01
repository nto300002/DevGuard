#!/usr/bin/env node

import { realpathSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runCheckStagedCommand } from "./staged-check.js";
import { formatHookInstallResult, installHooks } from "./hooks.js";
import { detectRoot, formatDoctorResult } from "./root.js";
import { runPushCheckCommand } from "./push-check.js";
import { loadConfig } from "./config.js";
import { applySecurityAllowlist, applySecurityBaseline, filterSecurityFindingsByMode, loadSecurityBaseline, scanRepositoryDetailed, type SecurityAnalysisIssue, type SecurityFinding, type SecurityScanMode } from "./security-check.js";

const helpText = `DevGuard

使い方:
  devguard doctor
  devguard init
  devguard check --staged
  devguard check --staged-diff
  devguard check --worktree-diff
  devguard check --all-diff
  devguard security-check
  devguard security-check --json
  devguard security-check --sarif
  devguard security-check --mode general
  devguard security-check --write-baseline
  devguard push-check
  devguard install-hooks [--include-submodules]
  devguard --help

AI開発向けのpre-commit / pre-pushセルフレビューCLIです。
`;

export function getHelpText(): string {
  return helpText;
}

export async function main(args = process.argv.slice(2)): Promise<number> {
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    process.stdout.write(getHelpText());
    return 0;
  }

  if (args[0] === "check" && (args[1] === "--staged" || args[1] === "--staged-diff" || args[1] === "--worktree-diff" || args[1] === "--all-diff")) {
    return runCheckStagedCommand(process.cwd(), {
      commandName: `check ${args[1]}`,
      diffScope: args[1] === "--worktree-diff" ? "worktree" : args[1] === "--all-diff" ? "all" : "staged",
    });
  }

  if (args[0] === "doctor") {
    const result = await detectRoot(process.cwd());
    process.stdout.write(formatDoctorResult(result));
    return 0;
  }

  if (args[0] === "install-hooks") {
    const root = await detectRoot(process.cwd());
    const result = await installHooks(root.gitRoot, {
      includeSubmodules: args.includes("--include-submodules"),
    });
    process.stdout.write(formatHookInstallResult(result));
    return 0;
  }

  if (args[0] === "push-check") {
    const root = await detectRoot(process.cwd());
    const scopeIndex = args.indexOf("--scope");
    return runPushCheckCommand(root.gitRoot, {
      agentBlock: args.includes("--agent-block"),
      scope: scopeIndex >= 0 ? args[scopeIndex + 1] : undefined,
    });
  }

  if (args[0] === "security-check") {
    const root = await detectRoot(process.cwd());
    const { config } = await loadConfig(root.gitRoot);
    const mode = securityScanMode(args);
    const scan = config.securityCheck.enabled ? await scanRepositoryDetailed(root.gitRoot, { excludePaths: config.securityCheck.excludePaths, astEnabled: config.securityCheck.astEnabled }) : { findings: [], analysisIssues: [] };
    if (args.includes("--write-baseline")) {
      const baselinePath = config.securityCheck.baselinePath ?? ".devguard-security-baseline.json";
      await writeFile(path.join(root.gitRoot, baselinePath), `${JSON.stringify({ findingIds: scan.findings.map((finding) => finding.id) }, null, 2)}\n`, "utf8");
      process.stdout.write(`Security baselineを書き出しました: ${baselinePath}\n検出件数: ${scan.findings.length}\n`);
      return 0;
    }
    const baseline = await loadSecurityBaseline(root.gitRoot, config.securityCheck.baselinePath);
    const findings = filterSecurityFindingsByMode(applySecurityBaseline(applySecurityAllowlist(scan.findings, config.securityCheck.allowlist), baseline), mode);
    process.stdout.write(args.includes("--sarif") ? formatSecurityCheckSarif(findings, scan.analysisIssues) : args.includes("--json") ? formatSecurityCheckJson(findings, scan.analysisIssues) : formatSecurityCheckResult(findings, scan.analysisIssues));
    const hasHighRisk = findings.some((finding) => finding.severity === "high" && !finding.suppressed);
    return hasHighRisk || (config.securityCheck.failOnUnparseable && scan.analysisIssues.length > 0) ? 1 : 0;
  }

  process.stderr.write(`不明なコマンド: ${args.join(" ")}\n`);
  process.stderr.write("使い方は devguard --help を確認してください。\n");
  return 1;
}

export function formatSecurityCheckResult(findings: SecurityFinding[], analysisIssues: SecurityAnalysisIssue[] = []): string {
  const suppressedCount = findings.filter((finding) => finding.suppressed).length;
  const lines = ["DevGuard security-check", `検出件数: ${findings.length}`, `抑制済み: ${suppressedCount}`];
  lines.push(`解析不能: ${analysisIssues.length}`);
  const activeFindings = findings.filter((finding) => !finding.suppressed);
  const byRule = new Map<string, number>();
  for (const finding of activeFindings) byRule.set(finding.ruleId, (byRule.get(finding.ruleId) ?? 0) + 1);
  if (byRule.size > 0) {
    lines.push("分類:");
    for (const [ruleId, count] of [...byRule.entries()].sort(([left], [right]) => left.localeCompare(right))) {
      lines.push(`- ${ruleId}: ${count}件`);
    }
  }
  if (analysisIssues.length > 0) {
    lines.push("解析不能ファイル:");
    for (const issue of analysisIssues) {
      lines.push(`- [${issue.language}] ${issue.filePath}: ${issue.message}`);
    }
  }
  if (findings.length === 0) {
    lines.push("検出結果: なし");
    return `${lines.join("\n")}\n`;
  }

  lines.push("検出結果:");
  for (const finding of findings) {
    const suppression = finding.suppressed ? " 抑制済み" : finding.suppressionExpired ? " 抑制期限切れ" : "";
    lines.push(`- [${formatSecuritySeverity(finding.severity)}${suppression}] ${finding.ruleId}: ${finding.filePath}:${finding.lineNumber}`);
    lines.push(`  Flow: ${finding.flow}`);
    lines.push(`  カテゴリ: ${finding.category}`);
    if (finding.cwe || finding.owaspCategory) lines.push(`  CWE/OWASP: ${finding.cwe ?? "-"} / ${finding.owaspCategory ?? "-"}`);
    lines.push(`  内容: ${finding.message}`);
    lines.push(`  対応: ${finding.remediation}`);
  }
  return `${lines.join("\n")}\n`;
}

function securityScanMode(args: string[]): SecurityScanMode {
  const index = args.indexOf("--mode");
  const value = index >= 0 ? args[index + 1] : undefined;
  if (value === "general" || value === "general-vulnerability") return "general-vulnerability";
  if (value === "security-flow") return "security-flow";
  return "all";
}

export function formatSecurityCheckJson(findings: SecurityFinding[], analysisIssues: SecurityAnalysisIssue[] = []): string {
  const activeFindings = findings.filter((finding) => !finding.suppressed);
  const byRule: Record<string, number> = {};
  for (const finding of activeFindings) byRule[finding.ruleId] = (byRule[finding.ruleId] ?? 0) + 1;
  return `${JSON.stringify({
    findings,
    analysisIssues,
    summary: {
      total: findings.length,
      active: activeFindings.length,
      suppressed: findings.length - activeFindings.length,
      high: activeFindings.filter((finding) => finding.severity === "high").length,
      medium: activeFindings.filter((finding) => finding.severity === "medium").length,
      low: activeFindings.filter((finding) => finding.severity === "low").length,
      unparseable: analysisIssues.length,
      byRule,
    },
  }, null, 2)}\n`;
}

export function formatSecurityCheckSarif(findings: SecurityFinding[], analysisIssues: SecurityAnalysisIssue[] = []): string {
  const rules = [...new Map(findings.map((finding) => [finding.ruleId, {
    id: finding.ruleId,
    name: finding.ruleId,
    shortDescription: { text: finding.message },
    helpUri: finding.cwe ? `https://cwe.mitre.org/data/definitions/${finding.cwe.replace("CWE-", "")}.html` : undefined,
  }])).values()];
  const results = findings.map((finding) => ({
    ruleId: finding.ruleId,
    level: sarifLevel(finding.severity),
    message: { text: finding.message },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: finding.filePath, uriBaseId: "%SRCROOT%" },
        region: { startLine: finding.lineNumber, startColumn: 1 },
      },
    }],
    properties: {
      category: finding.category,
      confidence: finding.confidence,
      severity: finding.severity,
      source: finding.source,
      sink: finding.sink,
      flow: finding.flow,
      remediation: finding.remediation,
      ...(finding.cwe ? { cwe: finding.cwe } : {}),
      ...(finding.owaspCategory ? { owaspCategory: finding.owaspCategory } : {}),
      ...(finding.suppressed ? { suppressed: true } : {}),
    },
  }));
  const notifications = analysisIssues.map((issue) => ({
    level: "error",
    message: { text: issue.message },
    locations: [{ physicalLocation: { artifactLocation: { uri: issue.filePath, uriBaseId: "%SRCROOT%" } } }],
    properties: { language: issue.language, kind: issue.kind },
  }));
  return `${JSON.stringify({
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{
      tool: { driver: { name: "DevGuard", informationUri: "https://github.com/nto300002/DevGuard", rules } },
      results,
      invocations: [{ executionSuccessful: analysisIssues.length === 0, toolExecutionNotifications: notifications }],
      columnKind: "utf16CodeUnits",
    }],
  }, null, 2)}\n`;
}

function sarifLevel(severity: SecurityFinding["severity"]): "error" | "warning" | "note" {
  return severity === "high" ? "error" : severity === "medium" ? "warning" : "note";
}

function formatSecuritySeverity(severity: SecurityFinding["severity"]): string {
  return { low: "低", medium: "中", high: "高" }[severity];
}

export function isDirectCliExecution(moduleUrl: string, argvPath: string | undefined): boolean {
  if (!argvPath) {
    return false;
  }

  return realpathSync(fileURLToPath(moduleUrl)) === realpathSync(argvPath);
}

const isDirectExecution = isDirectCliExecution(import.meta.url, process.argv[1]);

if (isDirectExecution) {
  const exitCode = await main();
  process.exitCode = exitCode;
}
