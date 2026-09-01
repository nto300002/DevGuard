import type { SecurityFinding } from "./security-check.js";

type RuntimeResult = {
  ruleId?: unknown;
  severity?: unknown;
  confidence?: unknown;
  path?: unknown;
  message?: unknown;
  cwe?: unknown;
};

export function validateStagingUrl(target: string): { valid: true } | { valid: false; reason: string } {
  try {
    const url = new URL(target);
    if (url.protocol !== "https:") return { valid: false, reason: "HTTPSのStaging URLが必要です。" };
    if (!/(?:^|[.-])(?:staging|stg)(?:[.-]|$)/i.test(url.hostname)) return { valid: false, reason: "本番環境の誤検査を防ぐため、stagingまたはstgを含むホスト名が必要です。" };
    return { valid: true };
  } catch {
    return { valid: false, reason: "URLを解析できません。" };
  }
}

export function parseRuntimeFindings(input: unknown, target: string): SecurityFinding[] {
  if (!validateStagingUrl(target).valid || !isRecord(input) || !Array.isArray(input.results)) return [];
  return input.results.flatMap((raw): SecurityFinding[] => {
    if (!isRecord(raw)) return [];
    const result = raw as RuntimeResult;
    const ruleId = typeof result.ruleId === "string" ? result.ruleId : "runtime-finding";
    const filePath = typeof result.path === "string" ? result.path : "/";
    const severity = normalizeSeverity(result.severity);
    const confidence = normalizeConfidence(result.confidence);
    if (!severity) return [];
    return [{
      id: `runtime:${ruleId}:${filePath}`,
      ruleId,
      language: "unknown",
      severity,
      confidence,
      filePath,
      lineNumber: 1,
      source: "user-input",
      sink: "http-client",
      flow: "runtime probe -> endpoint",
      message: sanitizeRuntimeText(typeof result.message === "string" ? result.message : "実行時検査で問題を検出しました。"),
      remediation: "Staging環境で再現手順を確認し、修正後にAPI/E2E/DASTを再実行してください。",
      category: "general-vulnerability",
      detectionOrigin: "runtime",
      cwe: typeof result.cwe === "string" ? result.cwe : undefined,
    }];
  });
}

function normalizeSeverity(value: unknown): SecurityFinding["severity"] | undefined {
  if (value === "critical") return "high";
  if (value === "moderate") return "medium";
  return value === "low" || value === "medium" || value === "high" ? value : undefined;
}

function normalizeConfidence(value: unknown): SecurityFinding["confidence"] {
  return value === "low" || value === "high" ? value : "medium";
}

function sanitizeRuntimeText(value: string): string {
  return value
    .replace(/https?:\/\/[^\s)]+/gi, "[URL]")
    .replace(/(?:token|secret|password|api[_-]?key)=([^\s&]+)/gi, "$1=[MASKED]");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
