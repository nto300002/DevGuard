import type { SecurityFinding, SecuritySeverity } from "./security-check.js";

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
