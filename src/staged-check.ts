import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { loadConfig, mergeDefaultKeywordDatabase, type DevGuardConfig, type KeywordRule } from "./config.js";
import { getStagedDiff, type ChangedFile, type DiffLine } from "./git-diff.js";

const execFileAsync = promisify(execFile);

export type ClassifiedFiles = {
  frontend: string[];
  backend: string[];
  db: string[];
  config: string[];
  test: string[];
  docs: string[];
  unknown: string[];
};

export type FindingSeverity = "low" | "medium" | "high";

export type KeywordFinding = {
  type: "keyword";
  id: string;
  ruleId: string;
  label: string;
  severity: FindingSeverity;
  filePath: string;
  lineNumber?: number;
  matchedPattern: string;
  preview: string;
  suppressed?: boolean;
  suppressionReason?: string;
};

export type LogFinding = {
  type: "log";
  id: string;
  kind: "static-log" | "variable-log" | "sensitive-log" | "logger-debug" | "print-variable" | "debugger-left";
  severity: "medium" | "high";
  filePath: string;
  lineNumber?: number;
  callee: string;
  argumentKind: "none" | "static" | "variable" | "sensitive" | "unknown";
  preview: string;
  suppressed?: boolean;
  suppressionReason?: string;
};

export type AnyFinding = KeywordFinding | LogFinding | { severity: FindingSeverity; suppressed?: boolean };

export type SuppressionComment = {
  ruleId: string;
  filePath: string;
  lineNumber: number;
  targetLineNumber: number;
  reason: string | null;
};

export type RiskResult = {
  level: "low" | "medium" | "high";
  score: number;
  exitCode: 0 | 1;
};

export type DiffSizeLevel = "compact" | "medium" | "large";

export type DiffSizeSummary = {
  fileCount: number;
  addedLineCount: number;
  removedLineCount: number;
  changedLineCount: number;
  level: DiffSizeLevel;
  warning?: string;
};

export type TestRecommendation = {
  id: string;
  command: string;
  reason: string;
};

export type ChecklistItem = {
  id: string;
  label: string;
  category: "common" | "frontend" | "backend" | "php";
};

export type CommitPlanItem = {
  title: string;
  files: string[];
};

export type StagedCheckResult = {
  files: ChangedFile[];
  classifiedFiles: ClassifiedFiles;
  keywordFindings: KeywordFinding[];
  logFindings: LogFinding[];
  suppressions: SuppressionComment[];
  risk: RiskResult;
  diffSize: DiffSizeSummary;
  recommendedTests: TestRecommendation[];
  checklist: ChecklistItem[];
  commitPlan: CommitPlanItem[];
};

export type RunCheckStagedCommandOptions = {
  commandName?: "check --staged" | "check --staged-diff";
};

export async function runStagedCheck(gitRoot: string): Promise<StagedCheckResult> {
  const [{ config }, stagedDiff] = await Promise.all([loadConfig(gitRoot), getStagedDiff(gitRoot)]);
  const classifiedFiles = classifyFiles(stagedDiff.files);
  const suppressions = parseSuppressionComments(stagedDiff.lines);
  const keywordFindings = applySuppressions(detectKeywordFindings(stagedDiff.lines), suppressions);
  const logFindings = applySuppressions(detectLogFindings(stagedDiff.lines), suppressions);

  return {
    files: stagedDiff.files,
    classifiedFiles,
    keywordFindings,
    logFindings,
    suppressions,
    risk: detectRisk([...keywordFindings, ...logFindings]),
    diffSize: evaluateDiffSize(stagedDiff.files, stagedDiff.lines),
    recommendedTests: resolveTestCommands(classifiedFiles, config),
    checklist: generateChecklist(classifiedFiles),
    commitPlan: suggestCommitPlan(classifiedFiles),
  };
}

export async function runCheckStagedCommand(cwd: string, options: RunCheckStagedCommandOptions = {}): Promise<number> {
  const gitRoot = (await runGit(cwd, ["rev-parse", "--show-toplevel"])).trim();
  const result = await runStagedCheck(gitRoot);
  process.stdout.write(formatStagedCheckResult(result, options.commandName));
  return result.risk.exitCode;
}

export function classifyFiles(files: ChangedFile[]): ClassifiedFiles {
  const classified: ClassifiedFiles = {
    frontend: [],
    backend: [],
    db: [],
    config: [],
    test: [],
    docs: [],
    unknown: [],
  };

  for (const file of files) {
    const filePath = file.path;
    if (isTestPath(filePath)) {
      classified.test.push(filePath);
      continue;
    }
    if (isDocPath(filePath)) {
      classified.docs.push(filePath);
      continue;
    }
    if (isDbPath(filePath)) {
      classified.db.push(filePath);
      continue;
    }
    if (isConfigPath(filePath)) {
      classified.config.push(filePath);
      continue;
    }
    if (isFrontendPath(filePath)) {
      classified.frontend.push(filePath);
      continue;
    }
    if (isBackendPath(filePath)) {
      classified.backend.push(filePath);
      continue;
    }
    classified.unknown.push(filePath);
  }

  return classified;
}

export function detectKeywordFindings(lines: DiffLine[], rules: KeywordRule[] = mergeDefaultKeywordDatabase()): KeywordFinding[] {
  const findings: KeywordFinding[] = [];

  for (const line of lines) {
    if (line.type !== "added") {
      continue;
    }

    for (const rule of rules) {
      if (!rule.targets.includes("addedLines")) {
        continue;
      }

      for (const pattern of rule.patterns) {
        if (matchesPattern(line.content, pattern, rule)) {
          findings.push({
            type: "keyword",
            id: `keyword:${rule.id}:${line.filePath}:${line.lineNumber}:${pattern}`,
            ruleId: rule.id,
            label: rule.label,
            severity: rule.severity,
            filePath: line.filePath,
            lineNumber: line.lineNumber,
            matchedPattern: pattern,
            preview: line.content.trim(),
            suppressed: false,
          });
        }
      }
    }
  }

  return findings;
}

export function detectLogFindings(lines: DiffLine[]): LogFinding[] {
  const findings: LogFinding[] = [];

  for (const line of lines) {
    if (line.type !== "added") {
      continue;
    }

    const content = line.content.trim();
    const common = {
      type: "log" as const,
      filePath: line.filePath,
      lineNumber: line.lineNumber,
      preview: content,
      suppressed: false,
    };

    if (/\bdebugger\b/.test(content)) {
      findings.push({ ...common, id: `log:debugger:${line.filePath}:${line.lineNumber}`, kind: "debugger-left", severity: "medium", callee: "debugger", argumentKind: "none" });
      continue;
    }

    const call = parseCall(content);
    if (!call) {
      continue;
    }

    if (call.callee === "console.log" || call.callee === "console.debug") {
      const argumentKind = classifyArgument(call.argument);
      findings.push({
        ...common,
        id: `log:${argumentKind}:${line.filePath}:${line.lineNumber}`,
        kind: argumentKind === "static" ? "static-log" : argumentKind === "sensitive" ? "sensitive-log" : "variable-log",
        severity: argumentKind === "static" ? "medium" : "high",
        callee: call.callee,
        argumentKind,
      });
      continue;
    }

    if (call.callee === "logger.debug" || call.callee === "logging.debug") {
      const argumentKind = classifyArgument(call.argument);
      findings.push({ ...common, id: `log:logger-debug:${line.filePath}:${line.lineNumber}`, kind: "logger-debug", severity: "high", callee: call.callee, argumentKind });
      continue;
    }

    if (call.callee === "print" || call.callee === "var_dump" || call.callee === "print_r" || call.callee === "dump" || call.callee === "dd") {
      const argumentKind = classifyArgument(call.argument);
      findings.push({ ...common, id: `log:print-variable:${line.filePath}:${line.lineNumber}`, kind: "print-variable", severity: "high", callee: call.callee, argumentKind });
    }
  }

  return findings;
}

export function parseSuppressionComments(lines: DiffLine[]): SuppressionComment[] {
  return lines.flatMap((line) => {
    if (line.type !== "added") {
      return [];
    }

    const match = /^\s*\/\/\s*devguard-disable-next-line\s+(?<ruleId>[a-zA-Z0-9_-]+)(?:\s+--\s+(?<reason>.+))?\s*$/.exec(line.content);
    if (!match?.groups) {
      return [];
    }

    return [
      {
        ruleId: match.groups.ruleId,
        filePath: line.filePath,
        lineNumber: line.lineNumber,
        targetLineNumber: line.lineNumber + 1,
        reason: match.groups.reason?.trim() || null,
      },
    ];
  });
}

export function applySuppressions<T extends KeywordFinding | LogFinding>(findings: T[], suppressions: SuppressionComment[]): T[] {
  return findings.map((finding) => {
    const suppression = suppressions.find((candidate) => {
      if (!candidate.reason) {
        return false;
      }
      return candidate.filePath === finding.filePath && candidate.targetLineNumber === finding.lineNumber && candidate.ruleId === getSuppressibleRuleId(finding);
    });

    if (!suppression) {
      return { ...finding, suppressed: false };
    }

    return {
      ...finding,
      suppressed: true,
      suppressionReason: suppression.reason ?? undefined,
    };
  });
}

export function resolveTestCommands(classified: ClassifiedFiles, config?: DevGuardConfig): TestRecommendation[] {
  const commands = config?.testCommands ?? {
    typecheck: { command: "npm run typecheck" },
    test: { command: "npm test" },
    "python-test": { command: "pytest" },
    "php-test": { command: "composer test" },
  };
  const recommendations = new Map<string, TestRecommendation>();

  if (classified.frontend.length > 0 || classified.config.some((file) => file === "package.json" || file.endsWith("tsconfig.json"))) {
    addRecommendation(recommendations, "typecheck", commands.typecheck?.command, "TypeScript or frontend files changed.");
    addRecommendation(recommendations, "test", commands.test?.command, "Frontend or shared behavior may be affected.");
  }

  if (classified.backend.length > 0 || classified.db.length > 0) {
    addRecommendation(recommendations, "python-test", commands["python-test"]?.command, "Backend or DB files changed.");
    addRecommendation(recommendations, "test", commands.test?.command, "Shared behavior may be affected.");
  }

  if (classified.config.some((file) => file === "composer.json" || file === "composer.lock") || classified.unknown.some((file) => file.endsWith(".php"))) {
    addRecommendation(recommendations, "php-test", commands["php-test"]?.command, "PHP files or Composer config changed.");
  }

  if (recommendations.size === 0) {
    addRecommendation(recommendations, "test", commands.test?.command, "General staged change check.");
  }

  return [...recommendations.values()];
}

export function generateChecklist(classified: ClassifiedFiles): ChecklistItem[] {
  const checklist: ChecklistItem[] = [
    { id: "common-related-tests", label: "Related tests or manual checks were performed.", category: "common" },
    { id: "common-happy-path", label: "Happy path was checked.", category: "common" },
    { id: "common-error-path", label: "Error path was checked.", category: "common" },
    { id: "common-ai-tests-read", label: "AI-generated tests were read.", category: "common" },
  ];

  if (classified.frontend.length > 0) {
    checklist.push(
      { id: "frontend-screen-opened", label: "Changed screen was opened.", category: "frontend" },
      { id: "frontend-states", label: "Error, loading, and empty states were checked.", category: "frontend" },
      { id: "frontend-public-secret", label: "NEXT_PUBLIC_ does not contain secret-like values.", category: "frontend" },
    );
  }

  if (classified.backend.length > 0 || classified.db.length > 0) {
    checklist.push(
      { id: "backend-route", label: "API route happy path was checked.", category: "backend" },
      { id: "backend-validation", label: "Validation error was checked.", category: "backend" },
      { id: "backend-db", label: "Migration or local DB behavior was checked when DB changes exist.", category: "backend" },
    );
  }

  if (classified.unknown.some((file) => file.endsWith(".php")) || classified.config.some((file) => file === "composer.json" || file === "composer.lock")) {
    checklist.push(
      { id: "php-debug", label: "var_dump, print_r, dd, and dump are not left behind.", category: "php" },
      { id: "php-env-example", label: ".env.example was updated for getenv or $_ENV additions.", category: "php" },
    );
  }

  return checklist;
}

export function detectRisk(findings: AnyFinding[]): RiskResult {
  const activeFindings = findings.filter((finding) => !finding.suppressed);
  if (activeFindings.some((finding) => finding.severity === "high")) {
    return { level: "high", score: 70, exitCode: 1 };
  }
  if (activeFindings.some((finding) => finding.severity === "medium")) {
    return { level: "medium", score: 30, exitCode: 0 };
  }
  return { level: "low", score: 0, exitCode: 0 };
}

export function evaluateDiffSize(files: ChangedFile[], lines: DiffLine[]): DiffSizeSummary {
  const fileCount = files.length;
  const addedLineCount = lines.filter((line) => line.type === "added").length;
  const removedLineCount = lines.filter((line) => line.type === "removed").length;
  const changedLineCount = addedLineCount + removedLineCount;

  if (fileCount >= 11 || changedLineCount >= 301) {
    return {
      fileCount,
      addedLineCount,
      removedLineCount,
      changedLineCount,
      level: "large",
      warning: "Staged diff is large. Split this work into smaller PRs before review.",
    };
  }

  if (fileCount >= 6 || changedLineCount >= 151) {
    return {
      fileCount,
      addedLineCount,
      removedLineCount,
      changedLineCount,
      level: "medium",
      warning: "Staged diff is getting large. Consider splitting this work into smaller PRs.",
    };
  }

  return {
    fileCount,
    addedLineCount,
    removedLineCount,
    changedLineCount,
    level: "compact",
  };
}

export function formatDiffSizeWarning(summary: DiffSizeSummary): string {
  const lines = [
    `- files: ${summary.fileCount}`,
    `- changed lines: ${summary.changedLineCount}`,
    `- added lines: ${summary.addedLineCount}`,
    `- removed lines: ${summary.removedLineCount}`,
    "PR size guide:",
    "- 1-5 files / <=150 changed lines: compact PR",
    "- 6-10 files or 151-300 changed lines: consider splitting",
    "- 11+ files or 301+ changed lines: split into smaller PRs",
  ];

  if (summary.warning) {
    lines.push(`Warning: ${summary.warning}`);
  }

  return lines.join("\n");
}

export function suggestCommitPlan(classified: ClassifiedFiles): CommitPlanItem[] {
  const plan: CommitPlanItem[] = [];
  const groups: Array<[keyof ClassifiedFiles, string]> = [
    ["frontend", "Frontend changes"],
    ["backend", "Backend changes"],
    ["db", "DB changes"],
    ["config", "Config changes"],
    ["test", "Test changes"],
    ["docs", "Docs changes"],
    ["unknown", "Other changes"],
  ];

  for (const [key, title] of groups) {
    if (classified[key].length > 0) {
      plan.push({ title, files: classified[key] });
    }
  }

  return plan;
}

export function formatStagedCheckResult(result: StagedCheckResult, commandName = "check --staged"): string {
  const lines: string[] = [];
  lines.push(`DevGuard ${commandName}`);
  lines.push(`Risk: ${result.risk.level}`);
  lines.push("");
  lines.push("Files:");
  if (result.files.length === 0) {
    lines.push("- none");
  } else {
    for (const file of result.files) {
      lines.push(`- ${file.path} (${file.status})`);
    }
  }

  lines.push("");
  lines.push("Diff size:");
  lines.push(formatDiffSizeWarning(result.diffSize));

  const findings = [...result.keywordFindings, ...result.logFindings];
  lines.push("");
  lines.push("Findings:");
  if (findings.length === 0) {
    lines.push("- none");
  } else {
    for (const finding of findings) {
      const suppressed = finding.suppressed ? " suppressed" : "";
      const label = finding.type === "keyword" ? finding.label : finding.kind;
      lines.push(`- [${finding.severity}${suppressed}] ${label}: ${finding.filePath}${finding.lineNumber ? `:${finding.lineNumber}` : ""} ${finding.preview}`);
    }
  }

  const highSuppressions = findings.filter((finding) => finding.severity === "high" && finding.suppressed);
  if (highSuppressions.length > 0) {
    lines.push("");
    lines.push("High severity suppressions:");
    for (const finding of highSuppressions) {
      lines.push(`- ${finding.filePath}:${finding.lineNumber} ${finding.suppressionReason}`);
    }
  }

  lines.push("");
  lines.push("Recommended tests:");
  for (const recommendation of result.recommendedTests) {
    lines.push(`- ${recommendation.command} (${recommendation.reason})`);
  }

  lines.push("");
  lines.push("Human checklist:");
  for (const item of result.checklist) {
    lines.push(`[ ] ${item.label}`);
  }

  lines.push("");
  lines.push("Commit plan:");
  for (const item of result.commitPlan) {
    lines.push(`- ${item.title}: ${item.files.join(", ")}`);
  }

  return `${lines.join("\n")}\n`;
}

function matchesPattern(content: string, pattern: string, rule: KeywordRule): boolean {
  if (rule.matchMode === "regex") {
    return new RegExp(pattern, rule.caseSensitive ? undefined : "i").test(content);
  }

  if (rule.caseSensitive) {
    return content.includes(pattern);
  }

  return content.toLowerCase().includes(pattern.toLowerCase());
}

function parseCall(content: string): { callee: string; argument: string } | null {
  const match = /\b(?<callee>console\.log|console\.debug|logger\.debug|logging\.debug|print|var_dump|print_r|dump|dd)\s*\((?<argument>.*)\)\s*;?$/.exec(content);
  if (!match?.groups) {
    return null;
  }
  return {
    callee: match.groups.callee,
    argument: match.groups.argument.trim(),
  };
}

function classifyArgument(argument: string): "none" | "static" | "variable" | "sensitive" | "unknown" {
  if (!argument) {
    return "none";
  }
  if (/(token|secret|password|credential|api[_-]?key)/i.test(argument)) {
    return "sensitive";
  }
  if (/^(['"`])(?:\\.|(?!\1).)*\1$/.test(argument)) {
    return "static";
  }
  return "variable";
}

function getSuppressibleRuleId(finding: KeywordFinding | LogFinding): string {
  if (finding.type === "keyword") {
    return finding.ruleId;
  }
  if (finding.kind === "variable-log" || finding.kind === "sensitive-log") {
    return "variable-log";
  }
  return finding.kind;
}

function addRecommendation(recommendations: Map<string, TestRecommendation>, id: string, command: string | undefined, reason: string): void {
  if (!command || recommendations.has(id)) {
    return;
  }
  recommendations.set(id, { id, command, reason });
}

function isFrontendPath(filePath: string): boolean {
  return /^(src\/components|components|src\/app|app\/.*\/page\.|src\/pages|pages)\//.test(filePath) || filePath === "middleware.ts";
}

function isBackendPath(filePath: string): boolean {
  return /^(app\/api|api|routers|routes|services|dependencies)\//.test(filePath) || filePath === "main.py";
}

function isDbPath(filePath: string): boolean {
  return /^(prisma|migrations|alembic|database|db|models)\//.test(filePath) || filePath === "alembic.ini";
}

function isConfigPath(filePath: string): boolean {
  return /(^|\/)(package\.json|package-lock\.json|pnpm-lock\.yaml|tsconfig\.json|requirements\.txt|pyproject\.toml|poetry\.lock|composer\.json|composer\.lock|\.env\.example)$/.test(filePath) || filePath.startsWith(".github/workflows/") || /^next\.config\./.test(filePath);
}

function isTestPath(filePath: string): boolean {
  return /(^|\/)(test|tests|__tests__)\//.test(filePath) || /\.(test|spec)\.[cm]?[jt]sx?$/.test(filePath);
}

function isDocPath(filePath: string): boolean {
  return filePath === "README.md" || filePath.startsWith("docs/") || /\.mdx?$/.test(filePath);
}

async function runGit(cwd: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync("git", args, { cwd });
  return stdout;
}
