import type { SecurityFinding } from "./security-check.js";

export type FixSuggestion = {
  findingId: string;
  ruleId: string;
  filePath: string;
  original: string;
  proposed: string;
  automatic: boolean;
  requiresApproval: boolean;
  applied: false;
};

export function generateFixSuggestions(findings: readonly SecurityFinding[], sources: ReadonlyMap<string, string>): FixSuggestion[] {
  return findings.map((finding) => {
    const original = sources.get(finding.filePath) ?? "";
    const proposed = proposedSource(finding, original);
    const automatic = finding.ruleId === "secret-to-log" && proposed !== original;
    return {
      findingId: finding.id,
      ruleId: finding.ruleId,
      filePath: finding.filePath,
      original,
      proposed,
      automatic,
      requiresApproval: !automatic,
      applied: false,
    };
  });
}

function proposedSource(finding: SecurityFinding, source: string): string {
  if (finding.ruleId !== "secret-to-log") return source;
  const lines = source.split(/(?<=\n)/);
  const index = finding.lineNumber - 1;
  if (!lines[index] || !/\b(?:console|logger|logging)\.(?:log|debug|info|warn|warning|error)\s*\(/.test(lines[index])) return source;
  lines[index] = lines[index].replace(/\([^\n]*\)/, "('[REDACTED]')");
  return lines.join("");
}
