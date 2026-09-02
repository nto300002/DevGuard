import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { SecurityAnalysisIssue, SecurityFinding, SecuritySeverity } from "./security-check.js";

const execFileAsync = promisify(execFile);

export type NpmAuditCommandResult = {
  stdout: string;
  stderr: string;
  status: number;
};

export type NpmAuditCommandRunner = (cwd: string) => Promise<NpmAuditCommandResult>;

export type NpmAuditResult = {
  findings: SecurityFinding[];
  analysisIssue?: SecurityAnalysisIssue;
};

export async function runNpmAudit(cwd: string, runner: NpmAuditCommandRunner = defaultNpmAuditRunner): Promise<NpmAuditResult> {
  const result = await runner(cwd);
  if (!result.stdout.trim()) {
    return {
      findings: [],
      analysisIssue: {
        filePath: "package-lock.json",
        language: "unknown",
        kind: "parse-error",
        message: result.stderr.trim() || `npm auditが終了コード${result.status}で終了し、JSON結果を返しませんでした。`,
      },
    };
  }

  try {
    return { findings: parseNpmAuditJson(JSON.parse(result.stdout)) };
  } catch {
    return {
      findings: [],
      analysisIssue: {
        filePath: "package-lock.json",
        language: "unknown",
        kind: "parse-error",
        message: "npm auditのJSON結果を解析できません。",
      },
    };
  }
}

async function defaultNpmAuditRunner(cwd: string): Promise<NpmAuditCommandResult> {
  try {
    const result = await execFileAsync("npm", ["audit", "--json"], { cwd, maxBuffer: 4 * 1024 * 1024 });
    return { stdout: result.stdout, stderr: result.stderr, status: 0 };
  } catch (error) {
    const failure = error as { stdout?: string; stderr?: string; code?: number };
    return { stdout: failure.stdout ?? "", stderr: failure.stderr ?? String(error), status: typeof failure.code === "number" ? failure.code : 1 };
  }
}

type NpmAuditVia = {
  source?: unknown;
  title?: unknown;
  url?: unknown;
};

type NpmAuditVulnerability = {
  severity?: unknown;
  range?: unknown;
  via?: unknown;
  fixAvailable?: unknown;
};

const SEVERITIES = new Set<SecuritySeverity>(["low", "medium", "high"]);

export function parseNpmAuditJson(input: unknown): SecurityFinding[] {
  if (!isRecord(input) || !isRecord(input.vulnerabilities)) return [];
  const findings: SecurityFinding[] = [];

  for (const [dependencyName, raw] of Object.entries(input.vulnerabilities)) {
    if (!isRecord(raw)) continue;
    const vulnerability = raw as NpmAuditVulnerability;
    const severity = normalizeSeverity(vulnerability.severity);
    if (!severity) continue;
    const advisory = firstAdvisory(vulnerability.via);
    const fixedVersion = isRecord(vulnerability.fixAvailable) && typeof vulnerability.fixAvailable.version === "string"
      ? vulnerability.fixAvailable.version
      : undefined;
    const advisoryId = advisory?.source ?? advisory?.url;
    findings.push({
      id: `dependency-vulnerability:${dependencyName}:${advisoryId ?? "unknown"}`,
      ruleId: "dependency-vulnerability",
      language: "unknown",
      severity,
      confidence: "high",
      filePath: "package-lock.json",
      lineNumber: 1,
      source: "dependency",
      sink: "package",
      flow: "dependency -> vulnerable package",
      message: `依存パッケージ ${dependencyName} に既知の脆弱性があります。${advisory?.title ? `概要: ${advisory.title}。` : ""}`,
      remediation: fixedVersion ? `${dependencyName}を${fixedVersion}以降へ更新してください。` : `${dependencyName}の修正版を確認して更新してください。`,
      category: "general-vulnerability",
      dependencyName,
      advisoryId,
      affectedRange: typeof vulnerability.range === "string" ? vulnerability.range : undefined,
      fixedVersion,
    });
  }

  return findings;
}

type PipAuditVulnerability = {
  id?: unknown;
  aliases?: unknown;
  fix_versions?: unknown;
  description?: unknown;
  severity?: unknown;
};

type PipAuditPackage = {
  name?: unknown;
  version?: unknown;
  vulns?: unknown;
};

export function parsePipAuditJson(input: unknown): SecurityFinding[] {
  if (!Array.isArray(input)) return [];
  const findings: SecurityFinding[] = [];

  for (const rawPackage of input) {
    if (!isRecord(rawPackage)) continue;
    const packageInfo = rawPackage as PipAuditPackage;
    if (typeof packageInfo.name !== "string" || typeof packageInfo.version !== "string" || !Array.isArray(packageInfo.vulns)) continue;
    for (const rawVulnerability of packageInfo.vulns) {
      if (!isRecord(rawVulnerability)) continue;
      const vulnerability = rawVulnerability as PipAuditVulnerability;
      const advisoryId = typeof vulnerability.id === "string" ? vulnerability.id : firstString(vulnerability.aliases);
      if (!advisoryId) continue;
      const fixedVersion = firstString(vulnerability.fix_versions);
      const title = typeof vulnerability.description === "string" ? vulnerability.description : undefined;
      findings.push({
        id: `dependency-vulnerability:${packageInfo.name}:${advisoryId}`,
        ruleId: "dependency-vulnerability",
        language: "python",
        severity: normalizeSeverity(vulnerability.severity) ?? "medium",
        confidence: "high",
        filePath: "requirements.txt",
        lineNumber: 1,
        source: "dependency",
        sink: "package",
        flow: "dependency -> vulnerable package",
        message: `依存パッケージ ${packageInfo.name} に既知の脆弱性があります。${title ? `概要: ${title}。` : ""}`,
        remediation: fixedVersion ? `${packageInfo.name}を${fixedVersion}以降へ更新してください。` : `${packageInfo.name}の修正版を確認して更新してください。`,
        category: "general-vulnerability",
        dependencyName: packageInfo.name,
        advisoryId,
        affectedRange: `==${packageInfo.version}`,
        fixedVersion,
      });
    }
  }

  return findings;
}

function firstString(value: unknown): string | undefined {
  return Array.isArray(value) ? value.find((item): item is string => typeof item === "string") : undefined;
}

function firstAdvisory(value: unknown): { source?: string; title?: string; url?: string } | undefined {
  if (!Array.isArray(value)) return undefined;
  const item = value.find((candidate): candidate is NpmAuditVia => isRecord(candidate) && (typeof candidate.source === "string" || typeof candidate.url === "string"));
  if (!item) return undefined;
  return {
    source: typeof item.source === "string" ? normalizeAdvisoryId(item.source, item.url) : typeof item.url === "string" ? normalizeAdvisoryId(item.url, item.url) : undefined,
    title: typeof item.title === "string" ? item.title : undefined,
    url: typeof item.url === "string" ? item.url : undefined,
  };
}

function normalizeAdvisoryId(source: string, url?: unknown): string {
  if (/^(?:CVE|GHSA)-[A-Z0-9-]+$/i.test(source)) return source;
  if (typeof url === "string") {
    const match = url.match(/(?:advisories|security-advisories)\/((?:CVE|GHSA)-[A-Z0-9-]+)/i);
    if (match) return match[1];
  }
  return source;
}

function normalizeSeverity(value: unknown): SecuritySeverity | undefined {
  if (value === "moderate") return "medium";
  return typeof value === "string" && SEVERITIES.has(value as SecuritySeverity) ? value as SecuritySeverity : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
