import { readdir, readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import phpParser from "php-parser";
import ts from "typescript";
import { parseDocument } from "yaml";
import type { SecurityAllowlistEntry } from "./config.js";
import type { DiffLine } from "./git-diff.js";

export type SecurityLanguage = "typescript" | "python" | "php" | "dart" | "yaml" | "dockerfile" | "unknown";
export type SecuritySeverity = "low" | "medium" | "high";
export type SecuritySource = "environment" | "request" | "secret" | "exception" | "user-input" | "sensitive-value";
export type SecuritySink = "logger" | "url" | "response" | "storage" | "deployment" | "sql" | "html" | "command" | "deserialization" | "file" | "http-client";
export type SecurityFindingCategory = "security-flow" | "general-vulnerability";
export type SecurityScanMode = "all" | SecurityFindingCategory;

export type SecurityFinding = {
  id: string;
  ruleId: string;
  language: SecurityLanguage;
  severity: SecuritySeverity;
  confidence: "low" | "medium" | "high";
  filePath: string;
  lineNumber: number;
  source: SecuritySource;
  sink: SecuritySink;
  flow: string;
  message: string;
  remediation: string;
  category: SecurityFindingCategory;
  cwe?: string;
  owaspCategory?: string;
  suppressed?: boolean;
  suppressionReason?: string;
  suppressionOwner?: string;
  suppressionExpired?: boolean;
  baseline?: boolean;
};

export type SecurityAnalysisIssue = {
  filePath: string;
  language: SecurityLanguage;
  kind: "parse-error" | "parser-unavailable";
  message: string;
};

export type SecurityScanTextResult = {
  findings: SecurityFinding[];
  analysisIssues: SecurityAnalysisIssue[];
};

export type SecurityRepositoryScanOptions = {
  excludePaths?: readonly string[];
};

export function filterSecurityFindingsByMode(findings: SecurityFinding[], mode: SecurityScanMode): SecurityFinding[] {
  return mode === "all" ? findings : findings.filter((finding) => finding.category === mode);
}

export async function loadSecurityBaseline(root: string, baselinePath: string | null): Promise<Set<string>> {
  if (!baselinePath) return new Set();
  try {
    const raw = JSON.parse(await readFile(path.join(root, baselinePath), "utf8")) as { findingIds?: unknown };
    if (!Array.isArray(raw.findingIds) || raw.findingIds.some((id) => typeof id !== "string")) {
      throw new Error("findingIds配列が必要です。");
    }
    return new Set(raw.findingIds);
  } catch (error) {
    if (error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT") return new Set();
    throw new Error(`Security baselineを読み込めません: ${baselinePath} (${error instanceof Error ? error.message : String(error)})`);
  }
}

export function applySecurityBaseline(findings: SecurityFinding[], baselineIds: ReadonlySet<string>): SecurityFinding[] {
  return findings.map((finding) => baselineIds.has(finding.id) ? { ...finding, suppressed: true, suppressionReason: "baseline", baseline: true } : finding);
}

// Dependency, virtual-environment, cache, and build directories are not application source.
// Keep this list conservative and name-based so generated files cannot inflate scan results.
const IGNORED_DIRECTORIES = new Set([
  ".git", ".idea", ".vscode",
  // TypeScript / JavaScript
  "node_modules", "bower_components", "dist", "build", ".next", "coverage",
  // Python
  ".venv", "venv", "env", "ENV", ".tox", ".nox", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
  // PHP
  "vendor", ".phpunit.cache",
  // Dart / Flutter
  ".dart_tool", ".pub-cache", "Pods",
]);
const SOURCE_PATTERNS: Array<{ source: SecuritySource; pattern: RegExp }> = [
  { source: "environment", pattern: /process\.env\b|import\.meta\.env\b|os\.(?:environ|getenv)\b|getenv\s*\(|\$_ENV\b|Platform\.environment\b/ },
  { source: "request", pattern: /request\.(?:json|body|query_params|args|form|headers|cookies)\s*\(|\$_(?:GET|POST|REQUEST|COOKIE)\b|req\.(?:query|body|headers|cookies)\b/ },
  { source: "exception", pattern: /str\s*\(\s*e\s*\)|exc\.(?:errors|detail)\b|(?:error|exception)\.(?:message|getMessage)\s*\(|\$e->getMessage\s*\(/i },
  { source: "secret", pattern: /\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|private[_-]?key|client[_-]?secret|jwt[_-]?secret|database[_-]?url)\b/i },
  { source: "user-input", pattern: /\b(?:user[_-]?input|payload|form[_-]?data|request[_-]?data)\b/i },
];

const SINK_PATTERNS: Array<{ sink: SecuritySink; pattern: RegExp }> = [
  { sink: "logger", pattern: /\b(?:console\.(?:log|debug|info|warn|error)|logger\.(?:debug|info|warning|warn|error)|logging\.(?:debug|info|warning|error)|print|debugPrint|var_dump|print_r|error_log|Log::(?:debug|info|warning|error))\s*\(/ },
  { sink: "url", pattern: /(?:\?|&)(?:token|access[_-]?token|reset[_-]?token|password|secret|api[_-]?key)=|Uri\.(?:parse|https?)\s*\(|(?:redirect|location)\s*\(/i },
  { sink: "response", pattern: /(?:JSONResponse|JsonResponse|Response|NextResponse|return\s+json|response\.json|res\.json)\s*\(/i },
  { sink: "storage", pattern: /(?:localStorage|sessionStorage|SharedPreferences|NSUserDefaults)\b/ },
  { sink: "deployment", pattern: /(?:secrets\.[A-Z0-9_]+|--substitutions|--update-env-vars|--set-env-vars|build-arg|\bARG\s+[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|KEY))/i },
];

const SECRET_FORMAT_PATTERNS: Array<{ ruleId: string; label: string; pattern: RegExp }> = [
  { ruleId: "secret-github-token", label: "GitHub token", pattern: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g },
  { ruleId: "secret-aws-access-key", label: "AWS access key", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { ruleId: "secret-stripe-key", label: "Stripe key", pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { ruleId: "secret-jwt", label: "JWT", pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { ruleId: "secret-private-key", label: "private key", pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { ruleId: "secret-connection-string", label: "database connection string", pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'`]+/gi },
];

export async function scanRepository(root: string, options: SecurityRepositoryScanOptions = {}): Promise<SecurityFinding[]> {
  return (await scanRepositoryDetailed(root, options)).findings;
}

export async function scanRepositoryDetailed(root: string, options: SecurityRepositoryScanOptions = {}): Promise<{ findings: SecurityFinding[]; analysisIssues: SecurityAnalysisIssue[] }> {
  const files = await collectSourceFiles(root);
  const findings: SecurityFinding[] = [];
  const analysisIssues: SecurityAnalysisIssue[] = [];

  for (const filePath of files) {
    const content = await readFile(filePath, "utf8");
    const relativePath = normalizePath(path.relative(root, filePath));
    if ((options.excludePaths ?? []).some((pattern) => matchesPath(pattern, relativePath))) continue;
    const result = scanTextDetailed(relativePath, content, languageForPath(relativePath));
    findings.push(...result.findings);
    analysisIssues.push(...result.analysisIssues);
  }

  return { findings, analysisIssues };
}

export function applySecurityAllowlist(findings: SecurityFinding[], entries: readonly SecurityAllowlistEntry[], now = new Date()): SecurityFinding[] {
  return findings.map((finding) => {
    const matchingEntries = entries.filter((entry) => matchesPath(entry.ruleId, finding.ruleId) && matchesPath(entry.filePath, finding.filePath));
    const activeEntry = matchingEntries.find((entry) => `${entry.expires}T23:59:59.999Z` >= now.toISOString());
    if (activeEntry) {
      return {
        ...finding,
        suppressed: true,
        suppressionReason: activeEntry.reason,
        suppressionOwner: activeEntry.owner,
      };
    }
    if (matchingEntries.length > 0) {
      return { ...finding, suppressed: false, suppressionExpired: true };
    }
    return { ...finding, suppressed: false };
  });
}

export function scanText(filePath: string, content: string, language: SecurityLanguage = languageForPath(filePath)): SecurityFinding[] {
  return scanTextDetailed(filePath, content, language).findings;
}

export function scanSecretPatterns(filePath: string, content: string, language: SecurityLanguage = languageForPath(filePath)): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  for (const { ruleId, label, pattern } of SECRET_FORMAT_PATTERNS) {
    for (const match of content.matchAll(pattern)) {
      const offset = match.index ?? 0;
      const lineNumber = content.slice(0, offset).split(/\r?\n/).length;
      findings.push(createFinding({
        filePath,
        lineNumber,
        language,
        ruleId,
        severity: "high",
        confidence: "high",
        source: "secret",
        sink: "file",
        flow: "secret literal -> source file",
        message: `${label}形式のSecretを検出しました（値: [MASKED]）。revoke / rotate後、リポジトリからremoveしてください。`,
        remediation: "漏えいしたSecretをrevokeし、新しい値へrotateしたうえで、履歴を含むリポジトリからremoveしてください。",
      }));
    }
  }
  return dedupeFindings(findings);
}

export function scanTextDetailed(filePath: string, content: string, language: SecurityLanguage = languageForPath(filePath)): SecurityScanTextResult {
  if (language === "typescript") {
    return addGeneralFindings(scanTypeScriptAstDetailed(filePath, content), filePath, content, language);
  }
  if (language === "python") {
    return addGeneralFindings(scanPythonAstDetailed(filePath, content), filePath, content, language);
  }
  if (language === "php") {
    return addGeneralFindings(scanPhpAstDetailed(filePath, content), filePath, content, language);
  }
  if (language === "dart") {
    const syntaxIssue = validateDartSyntax(filePath, content);
    return addGeneralFindings({ findings: scanLineFlows(filePath, content, language), analysisIssues: syntaxIssue ? [syntaxIssue] : [] }, filePath, content, language);
  }
  if (language === "yaml" || language === "dockerfile") {
    return scanDeploymentTextDetailed(filePath, content, language);
  }
  return { findings: scanLineFlows(filePath, content, language), analysisIssues: [] };
}

function addGeneralFindings(result: SecurityScanTextResult, filePath: string, content: string, language: SecurityLanguage): SecurityScanTextResult {
  return { ...result, findings: dedupeFindings([...result.findings, ...scanGeneralVulnerabilities(filePath, content, language), ...scanSecretPatterns(filePath, content, language)]) };
}

function scanGeneralVulnerabilities(filePath: string, content: string, language: SecurityLanguage): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const lines = content.split(/\r?\n/);
  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    const add = (ruleId: string, sink: SecuritySink, cwe: string, owaspCategory: string, message: string, remediation: string, confidence: SecurityFinding["confidence"] = "medium") => {
      findings.push(createFinding({ filePath, lineNumber, language, category: "general-vulnerability", ruleId, severity: "high", confidence, source: "user-input", sink, flow: `external input -> ${sink}`, cwe, owaspCategory, message, remediation }));
    };

    if (language === "typescript") {
      if (/\.(?:query|execute)\s*\([^)]*(?:\$\{|["'][^"']*["']\s*\+)/.test(line)) add("general-sqli", "sql", "CWE-89", "A03:2021-Injection", "外部入力を含むSQL文字列を実行している可能性があります。", "プレースホルダーとparameterized queryを使用してください。");
      if (/(?:innerHTML\s*=\s*(?!["'`])|dangerouslySetInnerHTML|insertAdjacentHTML) /.test(`${line} `)) add("general-xss", "html", "CWE-79", "A03:2021-Injection", "未検証の値がHTML/DOMへ挿入される可能性があります。", "出力エスケープまたは安全なHTMLサニタイズを使用してください。");
      if (/(?:child_process\.)?exec\s*\(\s*(?!["'`])|\beval\s*\(|new\s+Function\s*\(/.test(line)) add("general-command-injection", "command", "CWE-78", "A03:2021-Injection", "外部入力がコマンドまたはコード実行APIへ到達する可能性があります。", "固定コマンドと引数配列を使用し、外部入力を実行コードに渡さないでください。");
      if (/(?:fetch|axios\.(?:get|post|request)|http\.(?:get|request))\s*\([^"'`]/.test(line) && /(?:req\.|request|url|target|input)/i.test(line)) add("general-ssrf", "http-client", "CWE-918", "A10:2021-SSRF", "外部入力でHTTP接続先を指定できる可能性があります。", "許可リスト、URLスキーム検証、プライベートネットワーク遮断を実装してください。");
      if (/(?:readFile|writeFile|createReadStream|path\.join)\s*\([^"'`]/.test(line) && /(?:req\.|request|path|file|input)/i.test(line)) add("general-path-traversal", "file", "CWE-22", "A01:2021-Broken Access Control", "外部入力がファイルパスへ使われる可能性があります。", "実パスを検証し、許可ディレクトリ配下に正規化して制限してください。");
    }

    if (language === "python") {
      if (/(?:subprocess\.(?:run|call|Popen)|os\.system|os\.popen)\s*\(/.test(line) && /(?:request|input|payload|args|shell\s*=\s*True)/i.test(line)) add("general-command-injection", "command", "CWE-78", "A03:2021-Injection", "外部入力がコマンド実行APIへ到達する可能性があります。", "shell実行を避け、固定コマンドと引数配列を使用してください。");
      if (/(?:cursor|connection|db|session)\.(?:execute|query)\s*\(/.test(line) && /(?:f["']|\+|%|format\s*\()/i.test(line)) add("general-sqli", "sql", "CWE-89", "A03:2021-Injection", "動的なSQL文字列を実行している可能性があります。", "parameterized queryを使用してください。");
      if (/(?:pickle\.loads|yaml\.load)\s*\(/.test(line) && /(?:request|input|payload|data|body)/i.test(line)) add("general-unsafe-deserialization", "deserialization", "CWE-502", "A08:2021-Software and Data Integrity Failures", "外部入力を安全でない方式でデシリアライズする可能性があります。", "安全な形式へ変更し、型・スキーマ検証を行ってください。");
      if (/(?:requests?\.(?:get|post|request)|urllib\.request\.urlopen)\s*\(/.test(line) && /(?:request|url|target|input)/i.test(line)) add("general-ssrf", "http-client", "CWE-918", "A10:2021-SSRF", "外部入力でHTTP接続先を指定できる可能性があります。", "接続先を許可リストで制限してください。");
      if (/(?:open|Path\s*\()\s*\(/.test(line) && /(?:request|path|file|input)/i.test(line)) add("general-path-traversal", "file", "CWE-22", "A01:2021-Broken Access Control", "外部入力がファイルパスへ使われる可能性があります。", "パスを正規化し、許可ディレクトリ配下に制限してください。");
    }

    if (language === "php") {
      if (/(?:echo|print|printf)\s+.*\$_(?:GET|POST|REQUEST|COOKIE)/i.test(line)) add("general-xss", "html", "CWE-79", "A03:2021-Injection", "リクエスト値が未エスケープでHTMLへ出力される可能性があります。", "htmlspecialchars等で適切にエスケープしてください。");
      if (/(?:shell_exec|exec|system|passthru)\s*\(/i.test(line) && /\$_(?:GET|POST|REQUEST|COOKIE)|\$input|\$command/i.test(line)) add("general-command-injection", "command", "CWE-78", "A03:2021-Injection", "外部入力がコマンド実行APIへ到達する可能性があります。", "外部入力をコマンドとして連結せず、許可リストを使用してください。");
      if (/\bunserialize\s*\(/i.test(line) && /\$_(?:GET|POST|REQUEST|COOKIE)|\$input|\$data/i.test(line)) add("general-unsafe-deserialization", "deserialization", "CWE-502", "A08:2021-Software and Data Integrity Failures", "外部入力をunserializeしている可能性があります。", "JSON等の安全な形式へ変更し、クラス制限を行ってください。");
      if (/(?:include|require)(?:_once)?\s+.*\$_(?:GET|POST|REQUEST|COOKIE)/i.test(line)) add("general-path-traversal", "file", "CWE-22", "A01:2021-Broken Access Control", "外部入力がファイルincludeへ使われる可能性があります。", "ファイル名を許可リストで固定してください。");
      if (/(?:mysql_query|->(?:query|exec))\s*\(/i.test(line) && /\$_(?:GET|POST|REQUEST|COOKIE)|\$input|\$id/i.test(line)) add("general-sqli", "sql", "CWE-89", "A03:2021-Injection", "外部入力を含むSQLを実行している可能性があります。", "PDO prepared statement等を使用してください。");
    }

    if (language === "dart" && /(?:http\.(?:get|post|put|delete)|Uri\.parse)\s*\(/.test(line) && /(?:request|target|input)/i.test(line)) add("general-ssrf", "http-client", "CWE-918", "A10:2021-SSRF", "外部入力でHTTP接続先を指定できる可能性があります。", "接続先を許可リストで制限してください。");
  });
  return dedupeFindings(findings);
}

function validateDartSyntax(filePath: string, content: string): SecurityAnalysisIssue | null {
  const pairs = new Map<string, string>([[")", "("], ["]", "["], ["}", "{"]]);
  const opening = new Set(["(", "[", "{"]);
  const stack: Array<{ character: string; line: number }> = [];
  let quote: "'" | '"' | null = null;
  let escaped = false;
  let line = 1;
  let lineComment = false;
  let blockComment = false;

  for (let index = 0; index < content.length; index += 1) {
    const character = content[index];
    const next = content[index + 1];
    if (character === "\n") {
      line += 1;
      lineComment = false;
      continue;
    }
    if (lineComment) continue;
    if (blockComment) {
      if (character === "*" && next === "/") {
        blockComment = false;
        index += 1;
      }
      continue;
    }
    if (!quote && character === "/" && next === "/") {
      lineComment = true;
      index += 1;
      continue;
    }
    if (!quote && character === "/" && next === "*") {
      blockComment = true;
      index += 1;
      continue;
    }
    if (quote) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === quote) {
        quote = null;
      }
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      continue;
    }
    if (opening.has(character)) {
      stack.push({ character, line });
      continue;
    }
    if (pairs.has(character)) {
      const expected = stack.pop();
      if (!expected || expected.character !== pairs.get(character)) {
        return { filePath, language: "dart", kind: "parse-error", message: `${line}行目の括弧が対応していません。` };
      }
    }
  }

  if (quote || blockComment || stack.length > 0) {
    const location = stack.at(-1)?.line ?? line;
    return { filePath, language: "dart", kind: "parse-error", message: `${location}行目以降のDart構文を閉じられません。` };
  }
  return null;
}

/** Scan only added lines, preserving the original diff line numbers. */
export function scanDiffLinesDetailed(lines: readonly DiffLine[], options: SecurityRepositoryScanOptions = {}): SecurityScanTextResult {
  const findings: SecurityFinding[] = [];
  const analysisIssues: SecurityAnalysisIssue[] = [];
  const byFile = new Map<string, DiffLine[]>();

  for (const line of lines) {
    if (line.type !== "added" || (options.excludePaths ?? []).some((pattern) => matchesPath(pattern, line.filePath))) continue;
    const fileLines = byFile.get(line.filePath) ?? [];
    fileLines.push(line);
    byFile.set(line.filePath, fileLines);
  }

  for (const [filePath, fileLines] of byFile) {
    const result = scanTextDetailed(filePath, fileLines.map((line) => line.content).join("\n"), languageForPath(filePath));
    findings.push(...result.findings.map((finding) => ({
      ...finding,
      lineNumber: fileLines[finding.lineNumber - 1]?.lineNumber ?? finding.lineNumber,
    })));
    analysisIssues.push(...result.analysisIssues);
  }

  return { findings: dedupeFindings(findings), analysisIssues };
}

export function scanDiffLines(lines: readonly DiffLine[], options: SecurityRepositoryScanOptions = {}): SecurityFinding[] {
  return scanDiffLinesDetailed(lines, options).findings;
}

export async function scanDiffLinesFromRepository(root: string, lines: readonly DiffLine[], options: SecurityRepositoryScanOptions = {}): Promise<SecurityScanTextResult> {
  const addedLinesByFile = new Map<string, Set<number>>();
  for (const line of lines) {
    if (line.type !== "added" || (options.excludePaths ?? []).some((pattern) => matchesPath(pattern, line.filePath))) continue;
    const lineNumbers = addedLinesByFile.get(line.filePath) ?? new Set<number>();
    lineNumbers.add(line.lineNumber);
    addedLinesByFile.set(line.filePath, lineNumbers);
  }

  const findings: SecurityFinding[] = [];
  const analysisIssues: SecurityAnalysisIssue[] = [];
  for (const [filePath, addedLineNumbers] of addedLinesByFile) {
    let content: string;
    try {
      content = await readFile(path.join(root, filePath), "utf8");
    } catch {
      continue;
    }
    const result = scanTextDetailed(filePath, content, languageForPath(filePath));
    findings.push(...result.findings.filter((finding) => addedLineNumbers.has(finding.lineNumber)));
    analysisIssues.push(...result.analysisIssues);
  }
  return { findings: dedupeFindings(findings), analysisIssues };
}

function scanTypeScriptAst(filePath: string, content: string): SecurityFinding[] {
  return scanTypeScriptAstDetailed(filePath, content).findings;
}

function scanTypeScriptAstDetailed(filePath: string, content: string): SecurityScanTextResult {
  const sourceFile = ts.createSourceFile(filePath, content, ts.ScriptTarget.Latest, true, scriptKindForPath(filePath));
  const diagnostics = (sourceFile as unknown as { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
  if (diagnostics.length > 0) {
    return {
      findings: [],
      analysisIssues: [{ filePath, language: "typescript", kind: "parse-error", message: formatDiagnostic(diagnostics[0]) }],
    };
  }
  const tainted = new Map<string, SecuritySource>();
  const findings: SecurityFinding[] = [];

  const visit = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const source = sourceForTypeScriptExpression(node.initializer, tainted);
      if (source) tainted.set(node.name.text, source);
    }

    if (ts.isCallExpression(node)) {
      const sink = typeScriptSink(node.expression);
      const source = sourceForTypeScriptCall(node, tainted);
      if (sink && source) {
        const lineNumber = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
        const isUrl = sink === "url";
        findings.push(createFinding({
          filePath,
          lineNumber,
          language: "typescript",
          ruleId: isUrl ? "secret-in-url" : sink === "logger" ? (source === "request" ? "request-to-log" : source === "environment" || source === "secret" ? "secret-to-log" : "sensitive-to-log") : sink === "response" ? "sensitive-to-response" : "secret-to-storage",
          severity: "high",
          confidence: "high",
          source,
          sink,
          flow: `${source} -> ${sink}`,
          message: `${formatSource(source)}が${formatSink(sink)}へ流入する可能性があります。`,
          remediation: remediationForSink(sink),
        }));
      }
    }

    ts.forEachChild(node, visit);
  };

  visit(sourceFile);
  return { findings: dedupeFindings(findings), analysisIssues: [] };
}

function formatDiagnostic(diagnostic: ts.Diagnostic): string {
  return ts.flattenDiagnosticMessageText(diagnostic.messageText, " ");
}

function sourceForTypeScriptExpression(expression: ts.Expression, tainted: Map<string, SecuritySource>): SecuritySource | undefined {
  const text = expression.getText();
  const direct = SOURCE_PATTERNS.find(({ pattern }) => pattern.test(text))?.source;
  if (direct) return direct;
  for (const [variable, source] of tainted) {
    if (new RegExp(`(?:^|\\W)${escapeRegExp(variable)}(?=\\W|$)`).test(text)) return source;
  }
  if (isSensitiveVariable(text)) return "sensitive-value";
  return undefined;
}

function sourceForTypeScriptCall(node: ts.CallExpression, tainted: Map<string, SecuritySource>): SecuritySource | undefined {
  for (const argument of node.arguments) {
    const source = sourceForTypeScriptExpression(argument, tainted);
    if (source) return source;
  }
  if (typeScriptSink(node.expression) === "url" && containsCredentialQuery(node.getText())) return "secret";
  return undefined;
}

function typeScriptSink(expression: ts.Expression): SecuritySink | undefined {
  const text = expression.getText();
  if (/^(?:console|logger|logging)\.(?:log|debug|info|warn|warning|error)$/.test(text)) return "logger";
  if (/^(?:localStorage|sessionStorage)\.\w+$/.test(text)) return "storage";
  if (/^(?:Response|NextResponse|res)\.(?:json|redirect)$/.test(text)) return "response";
  if (/^(?:URL|URLSearchParams)\b/.test(text) || /^(?:redirect|location)$/.test(text)) return "url";
  return undefined;
}

function scriptKindForPath(filePath: string): ts.ScriptKind {
  if (filePath.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (filePath.endsWith(".jsx")) return ts.ScriptKind.JSX;
  return ts.ScriptKind.TS;
}

function scanPythonAst(filePath: string, content: string): SecurityFinding[] | null {
  const result = scanPythonAstDetailed(filePath, content);
  return result.analysisIssues.length > 0 ? null : result.findings;
}

function scanPythonAstDetailed(filePath: string, content: string): SecurityScanTextResult {
  const script = `import ast, json, sys\n\nsource = sys.stdin.read()\ntry:\n    tree = ast.parse(source)\nexcept SyntaxError:\n    print(json.dumps({"parse_error": True}))\n    raise SystemExit(0)\n\nsource_names = {}\nfindings = []\n\ndef names(node):\n    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}\n\ndef source_for(node):\n    text = ast.unparse(node) if hasattr(ast, "unparse") else ""\n    if "request" in text or "json()" in text or "query_params" in text or "request.data" in text:\n        return "request"\n    if "os.getenv" in text or "os.environ" in text or "getenv(" in text:\n        return "environment"\n    if "str(e)" in text or "getMessage" in text or "exception" in text.lower() or "exc.errors" in text:\n        return "exception"\n    if any(word in text.lower() for word in ("token", "secret", "password", "credential", "api_key")):\n        return "secret"\n    for name in names(node):\n        if name in source_names:\n            return source_names[name]\n    return None\n\nfor node in ast.walk(tree):\n    if isinstance(node, ast.Assign):\n        source = source_for(node.value)\n        if source:\n            for target in node.targets:\n                if isinstance(target, ast.Name): source_names[target.id] = source\n    if isinstance(node, ast.Call):\n        function = ast.unparse(node.func) if hasattr(ast, "unparse") else ""\n        sink = None\n        if function in ("logger.debug", "logger.info", "logger.warning", "logger.error", "logging.debug", "logging.info", "logging.warning", "logging.error", "print", "pprint", "error_log"):\n            sink = "logger"\n        elif function.endswith(".json") or function in ("JSONResponse", "JsonResponse"):\n            sink = "response"\n        elif function in ("redirect", "url_for"):\n            sink = "url"\n        if sink:\n            source = source_for(ast.Tuple(elts=node.args, ctx=ast.Load()))\n            if source:\n                rule = "request-to-log" if sink == "logger" and source == "request" else "secret-to-log" if sink == "logger" and source in ("environment", "secret") else "sensitive-to-log" if sink == "logger" else "sensitive-to-response" if sink == "response" else "secret-in-url"\n                findings.append({"line": node.lineno, "source": source, "sink": sink, "rule": rule})\nprint(json.dumps({"findings": findings}))`;

  const result = spawnSync("python3", ["-c", script], { input: content, encoding: "utf8", maxBuffer: 1024 * 1024 });
  if (result.error || result.status !== 0) {
    return { findings: [], analysisIssues: [{ filePath, language: "python", kind: "parser-unavailable", message: result.error?.message ?? "Python AST解析を実行できません。" }] };
  }
  try {
    const parsed = JSON.parse(result.stdout) as { parse_error?: boolean; findings?: Array<{ line: number; source: SecuritySource; sink: SecuritySink; rule: string }> };
    if (parsed.parse_error) return { findings: [], analysisIssues: [{ filePath, language: "python", kind: "parse-error", message: "Python構文を解析できません。" }] };
    return { findings: (parsed.findings ?? []).map((finding) => createFinding({
      filePath,
      lineNumber: finding.line,
      language: "python",
      ruleId: finding.rule,
      severity: "high",
      confidence: "high",
      source: finding.source,
      sink: finding.sink,
      flow: `${finding.source} -> ${finding.sink}`,
      message: `${formatSource(finding.source)}が${formatSink(finding.sink)}へ流入する可能性があります。`,
      remediation: remediationForSink(finding.sink),
    })), analysisIssues: [] };
  } catch {
    return { findings: [], analysisIssues: [{ filePath, language: "python", kind: "parser-unavailable", message: "Python AST解析結果を読み取れません。" }] };
  }
}

function scanPhpAst(filePath: string, content: string): SecurityFinding[] | null {
  const result = scanPhpAstDetailed(filePath, content);
  return result.analysisIssues.length > 0 ? null : result.findings;
}

function scanPhpAstDetailed(filePath: string, content: string): SecurityScanTextResult {
  try {
    const engine = new phpParser.Engine({ parser: { php7: true }, ast: { withPositions: true } });
    const hasPhpTag = /<\?php/i.test(content);
    const ast = engine.parseCode(hasPhpTag ? content : `<?php\n${content}`, filePath) as unknown as PhpNode;
    const tainted = new Map<string, SecuritySource>();
    const findings: SecurityFinding[] = [];

    walkPhp(ast, (node) => {
      if (node.kind === "assign" && node.left?.kind === "variable" && node.left.name) {
        const source = sourceForPhpNode(node.right, tainted);
        if (source) tainted.set(node.left.name, source);
      }

      if (node.kind !== "call" || !node.what) return;
      const functionName = phpNodeText(node.what);
      const sink = phpSink(functionName);
      if (!sink) return;
      const source = (node.arguments ?? []).map((argument) => sourceForPhpNode(argument, tainted)).find(Boolean);
      if (!source) return;
      const lineNumber = Math.max(1, (node.loc?.start?.line ?? 1) - (hasPhpTag ? 0 : 1));
      findings.push(createFinding({
        filePath,
        lineNumber,
        language: "php",
        ruleId: sink === "logger" ? (source === "request" ? "request-to-log" : source === "environment" || source === "secret" ? "secret-to-log" : "sensitive-to-log") : sink === "url" ? "secret-in-url" : sink === "response" ? "sensitive-to-response" : "secret-to-storage",
        severity: "high",
        confidence: "high",
        source,
        sink,
        flow: `${source} -> ${sink}`,
        message: `${formatSource(source)}が${formatSink(sink)}へ流入する可能性があります。`,
        remediation: remediationForSink(sink),
      }));
    });

    return { findings: dedupeFindings(findings), analysisIssues: [] };
  } catch (error) {
    return { findings: [], analysisIssues: [{ filePath, language: "php", kind: "parse-error", message: error instanceof Error ? error.message : "PHP構文を解析できません。" }] };
  }
}

function sourceForPhpNode(node: PhpNode | undefined, tainted: Map<string, SecuritySource>): SecuritySource | undefined {
  if (!node) return undefined;
  const text = phpNodeText(node);
  if (/\$_(?:GET|POST|REQUEST|COOKIE)\b/.test(text)) return "request";
  if (/\$_ENV\b|getenv\s*\(/.test(text)) return "environment";
  if (/getMessage\s*\(|exception|error/i.test(text)) return "exception";
  if (node.kind === "variable" && node.name) return tainted.get(node.name);
  if (isSensitiveVariable(text)) return "secret";
  for (const [variable, source] of tainted) {
    if (new RegExp(`(?:^|\\W)${escapeRegExp(variable)}(?=\\W|$)`).test(text)) return source;
  }
  return undefined;
}

function phpSink(functionName: string): SecuritySink | undefined {
  if (/^(?:error_log|var_dump|print_r|dump|dd|Log::(?:debug|info|warning|error))$/i.test(functionName)) return "logger";
  if (/^(?:redirect|header)$/i.test(functionName)) return "url";
  if (/^(?:json_encode|response|JsonResponse)$/i.test(functionName)) return "response";
  return undefined;
}

type PhpNode = {
  kind?: string;
  name?: string;
  what?: PhpNode;
  left?: PhpNode;
  right?: PhpNode;
  arguments?: PhpNode[];
  children?: PhpNode[];
  expression?: PhpNode;
  loc?: { start?: { line?: number } };
  [key: string]: unknown;
};

function walkPhp(node: PhpNode, visitor: (node: PhpNode) => void, seen = new WeakSet<object>()): void {
  if (seen.has(node)) return;
  seen.add(node);
  visitor(node);
  for (const value of Object.values(node)) {
    if (!value || value === node.loc) continue;
    if (Array.isArray(value)) {
      for (const item of value) if (isPhpNode(item)) walkPhp(item, visitor, seen);
    } else if (isPhpNode(value)) {
      walkPhp(value, visitor, seen);
    }
  }
}

function isPhpNode(value: unknown): value is PhpNode {
  return typeof value === "object" && value !== null && typeof (value as { kind?: unknown }).kind === "string";
}

function phpNodeText(node: PhpNode): string {
  if (!node.kind) return "";
  if (node.kind === "variable") return `$${node.name ?? ""}`;
  if (node.kind === "name") return node.name ?? "";
  if (node.kind === "offsetlookup") return `${phpNodeText(node.what ?? {})}[${phpNodeText((node as { offset?: PhpNode }).offset ?? {})}]`;
  return [node.name, phpNodeText(node.what ?? {}), phpNodeText(node.left ?? {}), phpNodeText(node.right ?? {}), ...(node.arguments ?? []).map(phpNodeText)].filter(Boolean).join(" ");
}

function scanLineFlows(filePath: string, content: string, language: SecurityLanguage): SecurityFinding[] {
  const lines = content.split(/\r?\n/);
  const taintedVariables = new Map<string, SecuritySource>();
  const findings: SecurityFinding[] = [];

  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    const sourceMatches = SOURCE_PATTERNS.filter(({ pattern }) => pattern.test(line));
    const source = sourceMatches[0]?.source;

    for (const variable of extractAssignedVariables(line)) {
      if (source) {
        taintedVariables.set(variable, source);
      } else if (isSensitiveVariable(variable)) {
        taintedVariables.set(variable, "sensitive-value");
      }
    }

    const sinkMatches = SINK_PATTERNS.filter(({ pattern }) => pattern.test(line));
    for (const { sink } of sinkMatches) {
      const variableSource = [...taintedVariables.entries()].find(([variable]) => variableAppears(line, variable))?.[1]
        ?? undefined;
      const directSource = source ?? inferSensitiveSource(line);
      const effectiveSource = variableSource ?? directSource;

      if (sink === "url" && containsCredentialQuery(line)) {
        for (const variable of extractAssignedVariables(line)) {
          taintedVariables.set(variable, effectiveSource ?? "secret");
        }
        findings.push(createFinding({ filePath, lineNumber, language, ruleId: "secret-in-url", severity: "high", source: effectiveSource ?? "secret", sink, flow: "sensitive value -> URL query", message: "認証情報またはSecretがURL queryへ流入する可能性があります。", remediation: "tokenやSecretをURL queryへ渡さず、POST body等の経路を検討してください。" }));
        continue;
      }

      if (sink === "deployment" && (source === "secret" || /secrets\./i.test(line))) {
        findings.push(createFinding({ filePath, lineNumber, language, ruleId: "secret-to-deployment", severity: "high", source: "secret", sink, flow: "Secret -> deployment configuration", message: "Secretがビルドまたはデプロイ設定へ直接流入しています。", remediation: "Secret Manager参照など、Secret実値をコマンド引数へ渡さない方式を検討してください。" }));
        continue;
      }

      if (!effectiveSource) {
        continue;
      }

      const ruleId = sink === "logger" ? (effectiveSource === "request" ? "request-to-log" : effectiveSource === "environment" || effectiveSource === "secret" ? "secret-to-log" : "sensitive-to-log") : sink === "response" ? "sensitive-to-response" : sink === "storage" ? "secret-to-storage" : "sensitive-flow";
      findings.push(createFinding({ filePath, lineNumber, language, ruleId, severity: "high", source: effectiveSource, sink, flow: `${effectiveSource} -> ${sink}`, message: `${formatSource(effectiveSource)}が${formatSink(sink)}へ流入する可能性があります。`, remediation: remediationForSink(sink) }));
    }
  });

  return dedupeFindings(findings);
}

function scanDeploymentText(filePath: string, content: string, language: "yaml" | "dockerfile"): SecurityFinding[] | null {
  return scanDeploymentTextDetailed(filePath, content, language).findings;
}

function scanDeploymentTextDetailed(filePath: string, content: string, language: "yaml" | "dockerfile"): SecurityScanTextResult {
  if (language === "yaml") {
    const document = parseDocument(content);
    if (document.errors.length > 0) {
      return {
        findings: [],
        analysisIssues: [{ filePath, language, kind: "parse-error", message: document.errors[0]?.message ?? "YAMLを解析できません。" }],
      };
    }

    const findings: SecurityFinding[] = [];
    content.split(/\r?\n/).forEach((line, index) => {
      const hasSecretReference = /\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}|\bsecrets\.[A-Za-z0-9_]+\b/i.test(line);
      const unsafeDeploymentSink = /--(?:substitutions|update-env-vars|set-env-vars)\b|^\s*env\s*:/i.test(line);
      const safeSecretReference = /--(?:update-secrets|set-secrets)\b|secretmanager|secret-manager/i.test(line);
      if (hasSecretReference && unsafeDeploymentSink && !safeSecretReference) {
        findings.push(deploymentFinding(filePath, index + 1, "Secret -> deployment configuration"));
      }
    });
    return { findings: dedupeFindings(findings), analysisIssues: [] };
  }

  const secretArgs = new Set<string>();
  const findings: SecurityFinding[] = [];
  content.split(/\r?\n/).forEach((line, index) => {
    const arg = /^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)/i.exec(line);
    if (arg && isSensitiveVariable(arg[1])) secretArgs.add(arg[1]);

    const env = /^\s*ENV\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/i.exec(line);
    const usesSecretArg = env && secretArgs.has(env[1]);
    const buildArgUsesSecret = /^\s*RUN\b.*--build-arg\s+([A-Za-z_][A-Za-z0-9_]*)\s*=/i.exec(line);
    if (usesSecretArg || (buildArgUsesSecret && secretArgs.has(buildArgUsesSecret[1]))) {
      findings.push(deploymentFinding(filePath, index + 1, "Secret -> deployment configuration"));
    }
  });
  return { findings: dedupeFindings(findings), analysisIssues: [] };
}

function deploymentFinding(filePath: string, lineNumber: number, flow: string): SecurityFinding {
  return createFinding({
    filePath,
    lineNumber,
    language: filePath.toLowerCase().endsWith("dockerfile") ? "dockerfile" : "yaml",
    ruleId: "secret-to-deployment",
    severity: "high",
    confidence: "high",
    source: "secret",
    sink: "deployment",
    flow,
    message: "Secretがビルドまたはデプロイ設定へ直接流入しています。",
    remediation: "Secret Manager参照など、Secret実値をコマンド引数へ渡さない方式を検討してください。",
  });
}

function createFinding(input: Omit<SecurityFinding, "id" | "confidence" | "category"> & { confidence?: SecurityFinding["confidence"]; category?: SecurityFindingCategory }): SecurityFinding {
  return {
    ...input,
    id: `${input.ruleId}:${input.filePath}:${input.lineNumber}`,
    confidence: input.confidence ?? "medium",
    category: input.category ?? "security-flow",
  };
}

function extractAssignedVariables(line: string): string[] {
  const matches = [...line.matchAll(/(?:const|let|var|final|val|var|\$)\s*([A-Za-z_][A-Za-z0-9_]*)\s*=|\b([A-Za-z_][A-Za-z0-9_]*)\s*=/g)];
  return matches.map((match) => match[1] ?? match[2]).filter(Boolean);
}

function isSensitiveVariable(variable: string): boolean {
  return /(?:token|secret|password|credential|api[_-]?key|private[_-]?key)/i.test(variable);
}

function variableAppears(line: string, variable: string): boolean {
  return new RegExp(`(?:^|\\W)${escapeRegExp(variable)}(?=\\W|$)`).test(line);
}

function inferSensitiveSource(line: string): SecuritySource | undefined {
  if (isSensitiveVariable(line)) return "secret";
  return undefined;
}

function containsCredentialQuery(line: string): boolean {
  return /(?:\?|&)(?:token|access[_-]?token|reset[_-]?token|password|secret|api[_-]?key)=/i.test(line);
}

function formatSource(source: SecuritySource): string {
  return { environment: "環境変数", request: "リクエスト入力", secret: "Secret", exception: "例外情報", "user-input": "ユーザー入力", "sensitive-value": "機密値" }[source];
}

function formatSink(sink: SecuritySink): string {
  return { logger: "ログ", url: "URL", response: "レスポンス", storage: "ストレージ", deployment: "デプロイ設定", sql: "SQL実行", html: "HTML/DOM", command: "コマンド実行", deserialization: "デシリアライズ", file: "ファイル操作", "http-client": "HTTP接続" }[sink];
}

function remediationForSink(sink: SecuritySink): string {
  return {
    logger: "値そのものではなく、固定メッセージ・error code・request id等へ置き換えてください。",
    url: "機密値をURLへ含めず、POST body等の経路を検討してください。",
    response: "raw inputや例外全文を返さず、固定のerror codeへ置き換えてください。",
    storage: "Secretを保存せず、必要な場合は安全なcredential storageを使用してください。",
    deployment: "Secret Manager参照を使用し、Secret実値をbuild引数やplain envへ渡さないでください。",
    sql: "プレースホルダーとparameterized queryを使用してください。",
    html: "出力エスケープまたは安全なHTMLサニタイズを使用してください。",
    command: "固定コマンドと引数配列を使用し、外部入力を実行コードに渡さないでください。",
    deserialization: "安全な形式へ変更し、型・スキーマ検証を行ってください。",
    file: "実パスを検証し、許可ディレクトリ配下に正規化して制限してください。",
    "http-client": "許可リスト、URLスキーム検証、プライベートネットワーク遮断を実装してください。",
  }[sink];
}

function languageForPath(filePath: string): SecurityLanguage {
  const lower = filePath.toLowerCase();
  if (/\.(ts|tsx|js|jsx)$/.test(lower)) return "typescript";
  if (lower.endsWith(".py")) return "python";
  if (lower.endsWith(".php")) return "php";
  if (lower.endsWith(".dart")) return "dart";
  if (lower.endsWith(".yml") || lower.endsWith(".yaml")) return "yaml";
  if (path.basename(lower) === "dockerfile") return "dockerfile";
  return "unknown";
}

async function collectSourceFiles(root: string): Promise<string[]> {
  const result: string[] = [];
  async function visit(directory: string): Promise<void> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.isDirectory() && IGNORED_DIRECTORIES.has(entry.name)) continue;
      const target = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(target);
        continue;
      }
      if (isScannablePath(entry.name)) result.push(target);
    }
  }
  await visit(root);
  return result.sort();
}

function isScannablePath(filePath: string): boolean {
  return /\.(ts|tsx|js|jsx|py|php|dart|yml|yaml)$/.test(filePath.toLowerCase()) || path.basename(filePath).toLowerCase() === "dockerfile";
}

function dedupeFindings(findings: SecurityFinding[]): SecurityFinding[] {
  return [...new Map(findings.map((finding) => [finding.id, finding])).values()];
}

function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, "/");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function matchesPath(pattern: string, filePath: string): boolean {
  const expression = `^${pattern.split("*").map(escapeRegExp).join(".*")}$`;
  return new RegExp(expression).test(filePath);
}
