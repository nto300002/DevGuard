import type { SecurityFinding, SecuritySeverity } from "./security-check.js";

export type HumanGatePolicy = {
  minimumSeverity: SecuritySeverity;
  minimumConfidence: SecurityFinding["confidence"];
};

export type HumanGateItem = {
  finding: SecurityFinding;
  filePath: string;
  reason: string;
  recommendedTests: string[];
  approvers: string[];
};

export type HumanGateResult = {
  required: boolean;
  items: HumanGateItem[];
};

const DEFAULT_POLICY: HumanGatePolicy = { minimumSeverity: "high", minimumConfidence: "medium" };
const SEVERITY_RANK: Record<SecuritySeverity, number> = { low: 1, medium: 2, high: 3 };
const CONFIDENCE_RANK: Record<SecurityFinding["confidence"], number> = { low: 1, medium: 2, high: 3 };

export function evaluateHumanGate(findings: readonly SecurityFinding[], policy: HumanGatePolicy = DEFAULT_POLICY): HumanGateResult {
  const items = findings
    .filter((finding) => !finding.suppressed && !finding.baseline)
    .filter((finding) => isGateCandidate(finding, policy))
    .map((finding) => ({
      finding,
      filePath: finding.filePath,
      reason: reasonForFinding(finding),
      recommendedTests: recommendedTestsForFinding(finding),
      approvers: [],
    }));
  return { required: items.length > 0, items };
}

export function formatHumanGateComment(result: HumanGateResult): string {
  if (!result.required) return "## Human Gate: 不要\n\nHighリスクの未承認Findingはありません。";
  const lines = ["## Human Gate: 承認が必要", "", "以下の変更は人間による確認後にマージしてください。", ""];
  for (const item of result.items) {
    lines.push(`- ${item.finding.ruleId} — ${item.filePath}:${item.finding.lineNumber}`);
    lines.push(`  - 理由: ${item.reason}`);
    lines.push(`  - 推奨テスト: ${item.recommendedTests.join("、")}`);
    lines.push("  - 承認者: 未指定");
  }
  return `${lines.join("\n")}\n`;
}

function isGateCandidate(finding: SecurityFinding, policy: HumanGatePolicy): boolean {
  const protectedRule = /^(?:secret|auth|general-(?:sqli|command-injection|path-traversal)|dependency-vulnerability)/i.test(finding.ruleId);
  return protectedRule || (SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[policy.minimumSeverity] && CONFIDENCE_RANK[finding.confidence] >= CONFIDENCE_RANK[policy.minimumConfidence]);
}

function reasonForFinding(finding: SecurityFinding): string {
  if (finding.source === "secret" || /^secret/i.test(finding.ruleId)) return "Secret・認証情報に関わる変更";
  if (finding.sink === "sql") return "DBクエリに関わる変更";
  if (finding.sink === "deployment") return "デプロイ設定に関わる変更";
  if (finding.sink === "response") return "公開APIレスポンスに関わる変更";
  return `${finding.severity}リスクかつ${finding.confidence} confidenceの検出`;
}

function recommendedTestsForFinding(finding: SecurityFinding): string[] {
  if (finding.sink === "sql") return ["parameterized queryテスト", "認可テスト"];
  if (finding.sink === "deployment") return ["デプロイ設定のdry-run", "Secret参照テスト"];
  if (finding.source === "secret") return ["Secret revoke / rotate確認", "漏えい経路の回帰テスト"];
  return ["関連ユニットテスト", "セキュリティ回帰テスト"];
}
