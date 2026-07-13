import { readFile } from "node:fs/promises";
import { loadConfig, type DevGuardConfig } from "./config.js";
import { getDefaultBranchDiff, type ChangedFile, type DiffLine } from "./git-diff.js";
import { detectLogFindings, type LogFinding } from "./staged-check.js";

export type EnvFinding = {
  name: string;
  source: "process.env" | "import.meta.env" | "os.environ" | "os.getenv" | "getenv" | "php.env" | "github.secrets" | "github.vars" | "github.env";
  filePath: string;
  lineNumber?: number;
  missingEnvExample: boolean;
};

export type ScopeFinding = {
  filePath: string;
  category: "db" | "config" | "env";
  scope: string;
};

export type PushBlockedReason = "env_secrets_added" | "out_of_scope_db_config" | "personal_strict_variable_log";

export type PushTodo = {
  id: string;
  label: string;
  category: "env" | "scope" | "log" | "test" | "pr";
  relatedFiles: string[];
  required: boolean;
};

export type PushCheckResult = {
  pushAllowed: boolean;
  riskLevel: "low" | "medium" | "high";
  blockedReasons: PushBlockedReason[];
  envFindings: EnvFinding[];
  scopeFindings: ScopeFinding[];
  logFindings: LogFinding[];
  todos: PushTodo[];
  agentBlock?: string;
};

export type PushCheckOptions = {
  agentBlock?: boolean;
  scope?: string;
};

type TodoInput = {
  envFindings: Array<Pick<EnvFinding, "name" | "source" | "filePath" | "lineNumber" | "missingEnvExample">>;
  scopeFindings: ScopeFinding[];
  logFindings: Array<Pick<LogFinding, "filePath" | "lineNumber" | "kind">>;
};

export async function runPushCheck(gitRoot: string, options: PushCheckOptions = {}): Promise<PushCheckResult> {
  const { config } = await loadConfig(gitRoot);
  const defaultBranch = resolveDefaultBranch(config);
  const diff = await getDefaultBranchDiff(gitRoot, defaultBranch);
  const envExampleKeys = await readEnvExampleKeys(gitRoot);
  const envFindings = config.envConsistency.enabled ? envConsistencyCheck(diff.lines, envExampleKeys) : [];
  const scope = options.scope ?? "frontend";
  const scopeFindings = config.issueScope.enabled ? issueScopeCheck(diff.files, scope ?? options.scope ?? "frontend") : [];
  const logFindings = detectLogFindings(diff.lines).filter((finding) => !finding.suppressed && (finding.kind === "variable-log" || finding.kind === "sensitive-log" || finding.kind === "logger-debug" || finding.kind === "print-variable"));
  const blockedReasons = getBlockedReasons({ envFindings, scopeFindings, logFindings, config });
  const todos = generatePushTodos({ envFindings, scopeFindings, logFindings });
  const pushAllowed = blockedReasons.length === 0;
  const files = collectRelatedFiles(envFindings, scopeFindings, logFindings);

  return {
    pushAllowed,
    riskLevel: pushAllowed ? (todos.length > 0 ? "medium" : "low") : "high",
    blockedReasons,
    envFindings,
    scopeFindings,
    logFindings,
    todos,
    agentBlock: !pushAllowed && (options.agentBlock || config.pushCheck.agentBlock) ? generateAgentBlock({ blockedReasons, files, todos }) : undefined,
  };
}

export async function runPushCheckCommand(gitRoot: string, options: PushCheckOptions): Promise<number> {
  const result = await runPushCheck(gitRoot, options);
  process.stdout.write(formatPushCheckResult(result));
  return result.pushAllowed ? 0 : 1;
}

export function envConsistencyCheck(lines: DiffLine[], existingEnvExampleKeys = new Set<string>()): EnvFinding[] {
  const envExampleKeys = new Set(existingEnvExampleKeys);
  for (const line of lines) {
    if (line.type === "added" && isEnvExamplePath(line.filePath)) {
      const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line.content);
      if (match) {
        envExampleKeys.add(match[1]);
      }
    }
  }

  const findings: EnvFinding[] = [];
  for (const line of lines) {
    if (line.type !== "added") {
      continue;
    }

    for (const ref of extractEnvRefs(line.content)) {
      findings.push({
        ...ref,
        filePath: line.filePath,
        lineNumber: line.lineNumber,
        missingEnvExample: !envExampleKeys.has(ref.name),
      });
    }
  }

  return dedupeEnvFindings(findings);
}

export function issueScopeCheck(files: ChangedFile[], scope = "frontend"): ScopeFinding[] {
  const findings: ScopeFinding[] = [];
  for (const file of files) {
    const category = getScopeCategory(file.path);
    if (!category) {
      continue;
    }
    if (scope === "frontend" && (category === "db" || category === "config" || category === "env")) {
      findings.push({ filePath: file.path, category, scope });
    }
  }
  return findings;
}

export function generatePushTodos(input: TodoInput): PushTodo[] {
  const todos: PushTodo[] = [
    {
      id: "test-related",
      label: "今回の変更に関係するテストまたは手動確認を行った",
      category: "test",
      relatedFiles: [],
      required: true,
    },
  ];

  for (const finding of input.envFindings) {
    todos.push(
      {
        id: `env-secret-${finding.name}`,
        label: `GitHub Repository Secrets または Environment Secrets に ${finding.name} を登録した`,
        category: "env",
        relatedFiles: [formatFileRef(finding.filePath, finding.lineNumber)],
        required: true,
      },
      {
        id: `env-example-${finding.name}`,
        label: `.env.example に ${finding.name} を追加した`,
        category: "env",
        relatedFiles: [".env.example"],
        required: finding.missingEnvExample,
      },
    );
  }

  if (input.scopeFindings.length > 0) {
    todos.push({
      id: "scope-confirm",
      label: "scope外DB/config変更をこのPRに含める必要がある",
      category: "scope",
      relatedFiles: input.scopeFindings.map((finding) => finding.filePath),
      required: true,
    });
  }

  if (input.logFindings.length > 0) {
    todos.push({
      id: "log-remove-or-justify",
      label: "変数logを削除、または残す理由を書いた",
      category: "log",
      relatedFiles: input.logFindings.map((finding) => formatFileRef(finding.filePath, finding.lineNumber)),
      required: true,
    });
  }

  todos.push({
    id: "pr-explain-risk",
    label: "PR本文にリスクと確認内容を書く",
    category: "pr",
    relatedFiles: [],
    required: false,
  });

  return dedupeTodos(todos);
}

export function generateAgentBlock(input: { blockedReasons: PushBlockedReason[]; files: string[]; todos: PushTodo[] }): string {
  return [
    "[DEVGUARD_AGENT_CONFIRMATION_REQUIRED]",
    "operation=git_push",
    `push_blocked=${input.blockedReasons.length > 0}`,
    `risk=${input.blockedReasons.length > 0 ? "high" : "medium"}`,
    "blocked_reasons:",
    ...input.blockedReasons.map((reason) => `- ${reason}`),
    "files:",
    ...(input.files.length > 0 ? input.files.map((file) => `- ${file}`) : ["- none"]),
    "required_user_confirmations:",
    "1. GitHub Secrets / Environment Secrets を設定済みですか？",
    "2. .env.example を更新済みですか？",
    "3. scope外DB/config変更をこのPRに含める必要がありますか？",
    "4. 変数logを削除、または残す理由を書きましたか？",
    "5. 今回の変更に関係するテストまたは手動確認を行いましたか？",
    "agent_instruction:",
    "- Do not run git push again.",
    "- Do not bypass hooks.",
    "- Ask the user the required_user_confirmations.",
    "- If the user confirms, explain the remaining risk before suggesting next action.",
    "[/DEVGUARD_AGENT_CONFIRMATION_REQUIRED]",
  ].join("\n");
}

export function formatPushCheckResult(result: PushCheckResult): string {
  const lines: string[] = [];
  lines.push(`Push: ${result.pushAllowed ? "allowed" : "blocked"}`);
  lines.push(`Risk: ${result.riskLevel}`);

  if (result.blockedReasons.length > 0) {
    lines.push("Reason:");
    for (const reason of result.blockedReasons) {
      lines.push(`- ${reason}`);
    }
  }

  lines.push("Files:");
  const files = collectRelatedFiles(result.envFindings, result.scopeFindings, result.logFindings);
  for (const file of files.length > 0 ? files : ["none"]) {
    lines.push(`- ${file}`);
  }

  if (result.envFindings.length > 0) {
    lines.push("Env / Secrets:");
    for (const finding of result.envFindings) {
      lines.push(`- ${finding.name}`);
      lines.push(`  source: ${finding.source}`);
      lines.push(`  file: ${formatFileRef(finding.filePath, finding.lineNumber)}`);
      lines.push(`  .env.example: ${finding.missingEnvExample ? "missing" : "ok"}`);
    }
  }

  if (result.scopeFindings.length > 0) {
    lines.push("Issue scope warning:");
    for (const finding of result.scopeFindings) {
      lines.push(`- ${finding.filePath}`);
      lines.push(`  category: ${finding.category}`);
    }
  }

  if (result.logFindings.length > 0) {
    lines.push("Log warnings:");
    for (const finding of result.logFindings) {
      lines.push(`- ${finding.kind}: ${formatFileRef(finding.filePath, finding.lineNumber)} ${finding.preview}`);
    }
  }

  lines.push("Todo:");
  for (const todo of result.todos) {
    lines.push(`[ ] ${todo.label}`);
  }

  if (result.agentBlock) {
    lines.push("");
    lines.push(result.agentBlock);
  }

  return `${lines.join("\n")}\n`;
}

function resolveDefaultBranch(config: DevGuardConfig): string {
  return config.project.defaultBranch || "main";
}

async function readEnvExampleKeys(gitRoot: string): Promise<Set<string>> {
  const keys = new Set<string>();
  for (const fileName of [".env.example", ".env.sample"]) {
    try {
      const content = await readFile(`${gitRoot}/${fileName}`, "utf8");
      for (const line of content.split(/\r?\n/)) {
        const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
        if (match?.[1]) {
          keys.add(match[1]);
        }
      }
    } catch {
      // Missing env example files are reported through missingEnvExample.
    }
  }
  return keys;
}

function getBlockedReasons(input: { envFindings: EnvFinding[]; scopeFindings: ScopeFinding[]; logFindings: LogFinding[]; config: DevGuardConfig }): PushBlockedReason[] {
  const reasons: PushBlockedReason[] = [];
  if (input.config.pushCheck.blockOn.envSecretsAdded && input.envFindings.length > 0) {
    reasons.push("env_secrets_added");
  }
  if (input.config.pushCheck.blockOn.outOfScopeDbConfig && input.scopeFindings.length > 0) {
    reasons.push("out_of_scope_db_config");
  }
  if (input.config.pushCheck.blockOn.personalStrictVariableLog && input.logFindings.length > 0) {
    reasons.push("personal_strict_variable_log");
  }
  return reasons;
}

function extractEnvRefs(content: string): Array<Pick<EnvFinding, "name" | "source">> {
  const refs: Array<Pick<EnvFinding, "name" | "source">> = [];
  collectRegex(refs, content, /process\.env\.([A-Za-z_][A-Za-z0-9_]*)/g, "process.env");
  collectRegex(refs, content, /import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)/g, "import.meta.env");
  collectRegex(refs, content, /os\.environ\[['"]([A-Za-z_][A-Za-z0-9_]*)['"]\]/g, "os.environ");
  collectRegex(refs, content, /os\.environ\.get\(['"]([A-Za-z_][A-Za-z0-9_]*)['"]\)/g, "os.environ");
  collectRegex(refs, content, /os\.getenv\(['"]([A-Za-z_][A-Za-z0-9_]*)['"]\)/g, "os.getenv");
  collectRegex(refs, content, /getenv\(['"]([A-Za-z_][A-Za-z0-9_]*)['"]\)/g, "getenv");
  collectRegex(refs, content, /\$_(?:ENV|SERVER)\[['"]([A-Za-z_][A-Za-z0-9_]*)['"]\]/g, "php.env");
  collectRegex(refs, content, /\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}/g, "github.secrets");
  collectRegex(refs, content, /\$\{\{\s*vars\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}/g, "github.vars");
  collectRegex(refs, content, /\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}/g, "github.env");
  return refs;
}

function collectRegex(refs: Array<Pick<EnvFinding, "name" | "source">>, content: string, regex: RegExp, source: EnvFinding["source"]): void {
  for (const match of content.matchAll(regex)) {
    const name = match[1];
    if (name) {
      refs.push({ name, source });
    }
  }
}

function getScopeCategory(filePath: string): ScopeFinding["category"] | null {
  if (/^(prisma|migrations|alembic|database|db|models)\//.test(filePath) || filePath === "alembic.ini") {
    return "db";
  }
  if (filePath.startsWith(".github/workflows/") || /(^|\/)(package\.json|package-lock\.json|pnpm-lock\.yaml|tsconfig\.json|requirements\.txt|pyproject\.toml|poetry\.lock|composer\.json|composer\.lock|\.env\.example)$/.test(filePath) || /^next\.config\./.test(filePath)) {
    return "config";
  }
  if (/\.env(\.|$)/.test(filePath)) {
    return "env";
  }
  return null;
}

function isEnvExamplePath(filePath: string): boolean {
  return filePath === ".env.example" || filePath === ".env.sample";
}

function dedupeEnvFindings(findings: EnvFinding[]): EnvFinding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.name}:${finding.source}:${finding.filePath}:${finding.lineNumber}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function dedupeTodos(todos: PushTodo[]): PushTodo[] {
  const seen = new Set<string>();
  return todos.filter((todo) => {
    if (seen.has(todo.id)) {
      return false;
    }
    seen.add(todo.id);
    return true;
  });
}

function collectRelatedFiles(envFindings: Array<Pick<EnvFinding, "filePath" | "lineNumber">>, scopeFindings: Array<Pick<ScopeFinding, "filePath">>, logFindings: Array<Pick<LogFinding, "filePath" | "lineNumber">>): string[] {
  return [
    ...envFindings.map((finding) => formatFileRef(finding.filePath, finding.lineNumber)),
    ...scopeFindings.map((finding) => finding.filePath),
    ...logFindings.map((finding) => formatFileRef(finding.filePath, finding.lineNumber)),
  ];
}

function formatFileRef(filePath: string, lineNumber?: number): string {
  return lineNumber ? `${filePath}:${lineNumber}` : filePath;
}
