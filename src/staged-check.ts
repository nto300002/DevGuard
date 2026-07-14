import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { loadConfig, mergeDefaultKeywordDatabase, type DevGuardConfig, type KeywordRule } from "./config.js";
import { getAllDiff, getStagedDiff, getWorktreeDiff, type ChangedFile, type DiffLine, type GitDiffResult } from "./git-diff.js";

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
  commandName?: "check --staged" | "check --staged-diff" | "check --worktree-diff" | "check --all-diff";
  diffScope?: "staged" | "worktree" | "all";
};

export async function runStagedCheck(gitRoot: string, diffScope: RunCheckStagedCommandOptions["diffScope"] = "staged"): Promise<StagedCheckResult> {
  const [{ config }, stagedDiff] = await Promise.all([loadConfig(gitRoot), getDiffByScope(gitRoot, diffScope)]);
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
  const result = await runStagedCheck(gitRoot, options.diffScope ?? "staged");
  process.stdout.write(formatStagedCheckResult(result, options.commandName));
  return result.risk.exitCode;
}

function getDiffByScope(gitRoot: string, diffScope: RunCheckStagedCommandOptions["diffScope"]): Promise<GitDiffResult> {
  if (diffScope === "worktree") {
    return getWorktreeDiff(gitRoot);
  }
  if (diffScope === "all") {
    return getAllDiff(gitRoot);
  }
  return getStagedDiff(gitRoot);
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
    { id: "common-related-tests", label: "関連するテストまたは手動確認を実施した", category: "common" },
    { id: "common-happy-path", label: "正常系を確認した", category: "common" },
    { id: "common-error-path", label: "異常系を確認した", category: "common" },
    { id: "common-ai-tests-read", label: "AIが生成したテスト内容を読んだ", category: "common" },
  ];

  if (classified.frontend.length > 0) {
    checklist.push(
      { id: "frontend-screen-opened", label: "変更した画面を開いた", category: "frontend" },
      { id: "frontend-states", label: "エラー・ローディング・空状態を確認した", category: "frontend" },
      { id: "frontend-public-secret", label: "NEXT_PUBLIC_ にsecretらしい値が含まれていない", category: "frontend" },
    );
  }

  if (classified.backend.length > 0 || classified.db.length > 0) {
    checklist.push(
      { id: "backend-route", label: "API routeの正常系を確認した", category: "backend" },
      { id: "backend-validation", label: "バリデーションエラーを確認した", category: "backend" },
      { id: "backend-db", label: "DB変更がある場合はmigrationまたはlocal DB挙動を確認した", category: "backend" },
    );
  }

  if (classified.unknown.some((file) => file.endsWith(".php")) || classified.config.some((file) => file === "composer.json" || file === "composer.lock")) {
    checklist.push(
      { id: "php-debug", label: "var_dump, print_r, dd, dump が残っていない", category: "php" },
      { id: "php-env-example", label: "getenv または $_ENV 追加時に .env.example を更新した", category: "php" },
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
      warning: "差分が大きすぎます。レビュー前に小さなPRへ分割してください。",
    };
  }

  if (fileCount >= 6 || changedLineCount >= 151) {
    return {
      fileCount,
      addedLineCount,
      removedLineCount,
      changedLineCount,
      level: "medium",
      warning: "差分が大きくなっています。小さなPRへの分割を検討してください。",
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
    `- ファイル数: ${summary.fileCount}`,
    `- 変更行数: ${summary.changedLineCount}`,
    `- 追加行数: ${summary.addedLineCount}`,
    `- 削除行数: ${summary.removedLineCount}`,
    "PRサイズ目安:",
    "- 1-5ファイル / 変更150行以下: 小さくまとまったPR",
    "- 6-10ファイル または 変更151-300行: PR分割を検討",
    "- 11ファイル以上 または 変更301行以上: 小さなPRに分割",
  ];

  if (summary.warning) {
    lines.push(`警告: ${summary.warning}`);
  }

  return lines.join("\n");
}

export function suggestCommitPlan(classified: ClassifiedFiles): CommitPlanItem[] {
  const plan: CommitPlanItem[] = [];
  const groups: Array<[keyof ClassifiedFiles, string]> = [
    ["frontend", "Frontend変更"],
    ["backend", "Backend変更"],
    ["db", "DB変更"],
    ["config", "設定変更"],
    ["test", "テスト変更"],
    ["docs", "ドキュメント変更"],
    ["unknown", "その他の変更"],
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
  lines.push(`リスク: ${formatSeverity(result.risk.level)}`);
  lines.push("");
  lines.push("ファイル:");
  if (result.files.length === 0) {
    lines.push("- なし");
  } else {
    for (const file of result.files) {
      lines.push(`- ${file.path} (${formatFileStatus(file.status)})`);
    }
  }

  lines.push("");
  lines.push("差分サイズ:");
  lines.push(formatDiffSizeWarning(result.diffSize));

  const findings = [...result.keywordFindings, ...result.logFindings];
  lines.push("");
  lines.push("検出結果:");
  if (findings.length === 0) {
    lines.push("- なし");
  } else {
    for (const finding of findings) {
      const suppressed = finding.suppressed ? " 抑制済み" : "";
      const label = finding.type === "keyword" ? formatKeywordLabel(finding.ruleId, finding.label) : formatLogKind(finding.kind);
      lines.push(`- [${formatSeverity(finding.severity)}${suppressed}] ${label}: ${finding.filePath}${finding.lineNumber ? `:${finding.lineNumber}` : ""} ${finding.preview}`);
    }
  }

  const highSuppressions = findings.filter((finding) => finding.severity === "high" && finding.suppressed);
  if (highSuppressions.length > 0) {
    lines.push("");
    lines.push("高リスクの抑制:");
    for (const finding of highSuppressions) {
      lines.push(`- ${finding.filePath}:${finding.lineNumber} ${finding.suppressionReason}`);
    }
  }

  lines.push("");
  lines.push("推奨テスト:");
  for (const recommendation of result.recommendedTests) {
    lines.push(`- ${recommendation.command} (${formatRecommendationReason(recommendation.reason)})`);
  }

  lines.push("");
  lines.push("人間の確認リスト:");
  for (const item of result.checklist) {
    lines.push(`[ ] ${item.label}`);
  }

  lines.push("");
  lines.push("コミット分割案:");
  for (const item of result.commitPlan) {
    lines.push(`- ${item.title}: ${item.files.join(", ")}`);
  }

  return `${lines.join("\n")}\n`;
}

function formatSeverity(severity: "low" | "medium" | "high"): string {
  return {
    low: "低",
    medium: "中",
    high: "高",
  }[severity];
}

function formatFileStatus(status: ChangedFile["status"]): string {
  return {
    added: "追加",
    modified: "変更",
    deleted: "削除",
    renamed: "リネーム",
    copied: "コピー",
    "type-changed": "種別変更",
    unmerged: "未マージ",
    unknown: "不明",
  }[status];
}

function formatKeywordLabel(ruleId: string, fallback: string): string {
  return (
    {
      "secrets-credentials": "Secrets / 認証情報",
      "work-in-progress": "作業途中マーカー",
      "ai-output-traces": "AI出力またはコピー跡",
      "bypass-markers": "チェック回避マーカー",
      "dangerous-apis": "危険API",
      "browser-storage-risk": "ブラウザストレージ使用",
      "destructive-db": "破壊的DB変更",
    }[ruleId] ?? fallback
  );
}

function formatLogKind(kind: LogFinding["kind"]): string {
  return {
    "static-log": "静的debug log",
    "variable-log": "変数debug log",
    "sensitive-log": "機密値debug log",
    "logger-debug": "logger debug",
    "print-variable": "変数print",
    "debugger-left": "debugger残留",
  }[kind];
}

function formatRecommendationReason(reason: string): string {
  return (
    {
      "TypeScript or frontend files changed.": "TypeScriptまたはfrontendファイルが変更されています。",
      "Frontend or shared behavior may be affected.": "Frontendまたは共有動作に影響する可能性があります。",
      "Backend or DB files changed.": "BackendまたはDBファイルが変更されています。",
      "Shared behavior may be affected.": "共有動作に影響する可能性があります。",
      "PHP files or Composer config changed.": "PHPファイルまたはComposer設定が変更されています。",
      "General staged change check.": "一般的な差分確認です。",
    }[reason] ?? reason
  );
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
  if (filePath === "middleware.ts") {
    return true;
  }

  if (/^(src\/)?(components|pages)\//.test(filePath)) {
    return true;
  }

  if (/^src\/(App|main|index)\.[cm]?[jt]sx?$/.test(filePath)) {
    return true;
  }

  if (/^(src\/)?app\//.test(filePath)) {
    return !/(^|\/)api\/|\/route\.[cm]?[jt]sx?$/.test(filePath);
  }

  return false;
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
