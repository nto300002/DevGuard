# DevGuard Detailed Design

## 1. Architecture Overview

DevGuard is a CLI application implemented in TypeScript and Node.js.

Core modules:

- CLI command router
- Git command adapter
- Git root detector
- Path normalizer
- Config loader and validator
- Diff collector
- Preset loader
- File classifier
- Keyword rule engine
- Log policy engine
- Suppression parser
- Environment consistency checker
- Issue scope checker
- Risk evaluator
- Checklist and todo generator
- Commit plan generator
- AI-agent confirmation block generator
- Hook installer

The implementation should favor simple, deterministic text and path analysis for the MVP. AST parsing and automatic code modification are intentionally out of scope.

## 2. Command Design

### `devguard doctor`

Responsibilities:

- Detect whether the current directory is inside a Git work tree.
- Detect whether the repository is bare.
- Resolve Git root.
- Resolve root-relative current directory.
- Resolve `.devguard.yml` path.
- Report whether config is loaded or default config is used.
- Confirm root-relative path normalization.

Failure behavior:

- Git management outside a work tree should be a controlled error.
- Internal Git command failures should return exit code `2`.

### `devguard init`

Responsibilities:

- Generate `.devguard.yml` at Git root.
- Refuse silent overwrite if the file already exists.
- Use the default config template from the requirements.

### `devguard check --staged`

Responsibilities:

- Collect staged file paths.
- Collect staged diff hunks.
- Normalize all file paths to root-relative `/` paths.
- Classify changed files.
- Run keyword rules against staged paths and diff lines.
- Run strict log detection.
- Parse and apply suppression comments.
- Generate recommended tests.
- Generate human review checklist.
- Generate commit split suggestions.
- Evaluate risk and return the correct exit code.

### `devguard push-check`

Responsibilities:

- Resolve default branch.
- Collect `defaultBranch...HEAD` diff.
- Detect environment and secrets additions.
- Detect out-of-scope DB/config changes.
- Detect remaining strict variable logs.
- Generate push confirmation todos.
- Generate AI-agent confirmation block when enabled.
- Evaluate push allow/block state.

### `devguard install-hooks`

Responsibilities:

- Install `pre-commit` and `pre-push` hooks.
- Preserve existing hooks and avoid silent overwrite.
- Make installed hooks executable.
- Use `npx devguard check --staged` for `pre-commit`.
- Use `npx devguard push-check --agent-block` for `pre-push`.

## 3. Internal Types

### Root Detection

```ts
type RootDetectionResult = {
  cwd: string;
  gitRoot: string;
  relativeCwdFromRoot: string;
  configPath: string | null;
  isInsideWorkTree: boolean;
  isBareRepository: boolean;
};
```

### Check Result

```ts
type CheckResult = {
  root: RootDetectionResult;
  files: ChangedFile[];
  classifiedFiles: ClassifiedFiles;
  diffStats: DiffStats;
  keywordFindings: KeywordFinding[];
  logFindings: LogFinding[];
  envFindings: EnvConsistencyFinding[];
  scopeFindings: IssueScopeFinding[];
  risk: RiskResult;
  recommendedTests: TestRecommendation[];
  checklist: ChecklistItem[];
  commitPlan: CommitPlanItem[];
};
```

### Push Check Result

```ts
type PushCheckResult = {
  pushAllowed: boolean;
  riskLevel: "low" | "medium" | "high";
  blockedReasons: PushBlockedReason[];
  envFindings: EnvConsistencyFinding[];
  scopeFindings: IssueScopeFinding[];
  logFindings: LogFinding[];
  todos: TodoItem[];
  agentBlock?: string;
};

type PushBlockedReason =
  | "env_secrets_added"
  | "out_of_scope_db_config"
  | "personal_strict_variable_log";
```

### Todo Item

```ts
type TodoItem = {
  id: string;
  label: string;
  category: "env" | "scope" | "log" | "test" | "pr";
  relatedFiles: string[];
  required: boolean;
};
```

### Log Finding

```ts
type LogFinding = {
  id: string;
  kind:
    | "static-log"
    | "variable-log"
    | "sensitive-log"
    | "logger-debug"
    | "print-variable"
    | "debugger-left";
  severity: "low" | "medium" | "high";
  filePath: string;
  lineNumber?: number;
  callee: string;
  argumentKind: "none" | "static" | "variable" | "sensitive" | "unknown";
  preview?: string;
  suppressed?: boolean;
  suppressionReason?: string;
};
```

### Suppression Comment

```ts
type SuppressionComment = {
  ruleId: string;
  filePath: string;
  lineNumber: number;
  targetLineNumber: number;
  reason: string | null;
};
```

## 4. Git and Path Processing

### Root Detection Flow

1. Run `git rev-parse --is-inside-work-tree`.
2. Run `git rev-parse --is-bare-repository`.
3. Run `git rev-parse --show-toplevel`.
4. Resolve current working directory.
5. Compute current directory relative to Git root.
6. Resolve `<git-root>/.devguard.yml`.

### Path Normalization

All paths are normalized by:

1. Resolving to an absolute path when necessary.
2. Ensuring the path is inside Git root.
3. Converting to Git-root relative path.
4. Replacing platform separators with `/`.

Files outside Git root are ignored.

## 5. Diff Processing

### Staged Diff

Use Git to collect:

- staged file list
- staged name status
- staged patch

Suggested commands:

```bash
git diff --cached --name-status
git diff --cached --unified=0
```

### Push Diff

Use:

```bash
git diff <defaultBranch>...HEAD --name-status
git diff <defaultBranch>...HEAD --unified=0
```

Default branch resolution:

1. `project.defaultBranch` from config
2. `main`
3. `master`

The MVP may use Git branch existence checks before selecting fallback branches.

## 6. Keyword Rules

```ts
type KeywordRule = {
  id: string;
  label: string;
  severity: "low" | "medium" | "high";
  targets: KeywordTarget[];
  patterns: string[];
  matchMode?: "contains" | "regex";
  caseSensitive?: boolean;
  excludePaths?: string[];
};

type KeywordTarget =
  | "addedLines"
  | "removedLines"
  | "filePath"
  | "commitMessage"
  | "branchName";
```

Default keyword groups:

- Secrets and credentials
- Work-in-progress markers
- AI output or copy-paste traces
- Check bypass markers
- Dangerous APIs
- Destructive DB changes
- MVP-out technology risk markers

Important secret keywords include:

- `API_KEY`
- `SECRET`
- `TOKEN`
- `PASSWORD`
- `PRIVATE_KEY`
- `DATABASE_URL`
- `JWT_SECRET`
- `SESSION_SECRET`
- `STRIPE_SECRET_KEY`
- `OPENAI_API_KEY`
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`

Work-in-progress markers include:

- `TODO`
- `FIXME`
- `WIP`
- `TEMP`
- `HACK`
- `あとで`
- `仮`
- `暫定`
- `未対応`
- `未実装`

Dangerous APIs include:

- `eval(`
- `Function(`
- `new Function`
- `innerHTML`
- `dangerouslySetInnerHTML`
- `document.write`
- `exec(`
- `system(`
- `shell_exec(`
- `subprocess.run`
- `os.system`

DB destructive markers include:

- `DROP TABLE`
- `DROP DATABASE`
- `TRUNCATE`
- `DELETE FROM`
- `ALTER TABLE`
- `CASCADE`
- `DROP COLUMN`
- `DROP INDEX`
- `rollback`
- `down migration`

## 7. Log Policy

The personal MVP uses `personalStrictLog`.

Config:

```yaml
logPolicy:
  preset: "personalStrictLog"
  aggregate: true
  maxExamplesPerGroup: 3
```

Log finding categories:

| Kind | Example | MVP Severity |
| --- | --- | --- |
| static-log | `console.log("loaded")` | Medium |
| variable-log | `console.log(user)` | High |
| sensitive-log | `console.log(token)` | High |
| logger-debug | `logger.debug(user)` | High |
| print-variable | `print(user)` | High |
| debugger-left | `debugger` | Medium |

Display behavior:

- Aggregate findings by kind.
- Show only a small number of examples by default.
- Show full details with `--verbose`.

## 8. Suppression Comments

Supported syntax:

```ts
// devguard-disable-next-line <ruleId> -- <reason>
console.log(debugInfo);
```

Rules:

- Reason is required for all severities.
- Suppression without reason is invalid and does not suppress the finding.
- MVP does not judge reason quality.
- High-severity suppressions must be summarized.

Supported targets:

- keyword rule findings
- log policy findings

Out of scope:

- file-level suppression
- multiline suppression
- suppressing all rules at once
- suppressing risk itself

## 9. Environment Consistency Check

### Detection Targets

- `process.env.X`
- `import.meta.env.X`
- `os.environ["X"]`
- `os.environ.get("X")`
- `os.getenv("X")`
- `getenv("X")`
- `$_ENV["X"]`
- `$_SERVER["X"]`
- `${{ secrets.X }}`
- `${{ vars.X }}`
- `${{ env.X }}`

### Target Files

- `.github/workflows/**`
- `.env.example`
- `.env.sample`
- `README.md`
- `docs/**`
- `src/**`
- `app/**`
- `requirements.txt`
- `pyproject.toml`
- `composer.json`

### Push Block Conditions

- A new `process.env.X` reference is added.
- A new `import.meta.env.X` reference is added.
- A new GitHub Actions `secrets.X` reference is added.
- A secret-like environment variable is added.
- `.env.example` does not contain the matching key.

### Todo Generation

Example todos:

- `[ ] GitHub Repository Secrets or Environment Secrets has the required key.`
- `[ ] Workflow reference name matches the actual secret name.`
- `[ ] .env.example includes the required variable.`
- `[ ] README or docs includes setup steps.`
- `[ ] The required environment has been identified: local, staging, or production.`

## 10. Issue Scope Check

The MVP does not fetch GitHub Issue bodies.

Scope is determined by:

- `devguard push-check --scope <scope>`
- `.devguard.yml` `issueScope.allowedScopes`

Push blockers:

- DB changes outside the selected scope
- config changes outside the selected scope
- environment/secrets changes outside the selected scope

Example output:

```text
Issue scope warning:
Current scope: frontend
Out-of-scope files:
- prisma/schema.prisma
  category: db
- package.json
  category: config
Todo:
[ ] This DB/config change must be included in this issue.
[ ] Splitting into another issue or PR has been considered.
[ ] PR body explains the out-of-scope change.
[ ] DB/config impact can be explained.
```

## 11. Manual Test Todos

### Common Todos

- `[ ] Related tests or manual checks were performed.`
- `[ ] Happy path was checked.`
- `[ ] Error path was checked.`
- `[ ] Changed screen, API, or DB operation was checked.`
- `[ ] AI-generated tests were read.`
- `[ ] Tests are not only written to pass implementation details.`

### FastAPI / Backend Todos

- `[ ] API route happy path was checked.`
- `[ ] Validation error was checked.`
- `[ ] Response schema impact was checked.`
- `[ ] CORS/auth/middleware impact was checked.`
- `[ ] Migration or local DB behavior was checked when DB changes exist.`

### Next.js / Frontend Todos

- `[ ] Changed screen was opened.`
- `[ ] Input and empty-input states were checked.`
- `[ ] Error, loading, and empty states were checked.`
- `[ ] API response changes match the UI.`
- [ ] Secret-like values are not placed in `NEXT_PUBLIC_` variables.

### PHP Todos

- [ ] `var_dump`, `print_r`, `dd`, and `dump` are not left behind.
- [ ] `.env.example` was updated for `getenv` or `$_ENV` additions.
- [ ] `composer.lock` changes were checked.
- [ ] Config change impact was checked.

## 12. Preset Details

### TypeScript

Log markers:

- `console.log(`
- `console.debug(`
- `debugger`
- `logger.debug(`

Env markers:

- `process.env.`

Risk markers:

- `as any`
- `@ts-ignore`
- `@ts-expect-error`
- `eslint-disable`
- `eval(`
- `innerHTML =`
- `dangerouslySetInnerHTML`

Config/dependency files:

- `package.json`
- `package-lock.json`
- `pnpm-lock.yaml`
- `yarn.lock`
- `bun.lockb`
- `tsconfig.json`
- `eslint.config.js`

### Next.js

Paths:

- `src/app/**`
- `app/**`
- `src/pages/**`
- `pages/**`
- `src/components/**`
- `components/**`
- `middleware.ts`
- `next.config.js`
- `next.config.mjs`
- `next.config.ts`

Env markers:

- `process.env.`
- `NEXT_PUBLIC_`
- `.env.local`
- `.env.production`
- `.env.development`

High-risk markers:

- `NEXT_PUBLIC_SECRET`
- `NEXT_PUBLIC_TOKEN`
- `NEXT_PUBLIC_API_KEY`
- `NEXT_PUBLIC_PASSWORD`
- `NEXT_PUBLIC_PRIVATE_KEY`
- `NEXT_PUBLIC_CLIENT_SECRET`
- `middleware.ts` changes
- `next.config.*` changes
- `.env.local` and `.env.production` related changes

### Python

Log markers:

- `print(`
- `logging.debug(`
- `pprint(`
- `breakpoint(`

Env markers:

- `os.environ`
- `os.getenv`
- `getenv(`
- `load_dotenv`

Dangerous APIs:

- `eval(`
- `exec(`
- `compile(`
- `os.system(`
- `subprocess.call(`
- `subprocess.run(`
- `subprocess.Popen(`
- `pickle.loads(`
- `yaml.load(`

Config/dependency files:

- `requirements.txt`
- `pyproject.toml`
- `poetry.lock`
- `Pipfile`
- `Pipfile.lock`
- `.env`
- `.env.example`

### FastAPI

Paths:

- `app/**`
- `src/**`
- `main.py`
- `routers/**`
- `routes/**`
- `schemas/**`
- `models/**`
- `services/**`
- `dependencies/**`

Settings/env markers:

- `BaseSettings`
- `SettingsConfigDict`
- `pydantic_settings`
- `os.getenv`
- `os.environ`

Route/schema markers:

- `@app.get`
- `@app.post`
- `@app.put`
- `@app.delete`
- `APIRouter`
- `response_model`
- `Depends(`
- `HTTPException`

Auth/CORS markers:

- `OAuth2PasswordBearer`
- `CORSMiddleware`
- `allow_origins`
- `allow_credentials`
- `Authorization`
- `Bearer`

DB/migration candidates:

- `alembic`
- `alembic.ini`
- `migrations/`
- `models/`
- `schemas/`
- `database/`
- `db/`

### PHP

Log/debug markers:

- `var_dump(`
- `print_r(`
- `dump(`
- `dd(`

`echo` is common application output, so it is not always high risk in the MVP unless explicitly configured.

Env markers:

- `getenv(`
- `$_ENV`
- `$_SERVER`

Dangerous APIs:

- `eval(`
- `exec(`
- `shell_exec(`
- `system(`
- `passthru(`
- `popen(`
- `unserialize(`
- `include(`
- `require(`

Config/dependency files:

- `composer.json`
- `composer.lock`
- `.env`
- `.env.example`
- `config/`

## 13. AI-Agent Confirmation Block

When push is blocked and agent block output is enabled, DevGuard emits:

```text
[DEVGUARD_AGENT_CONFIRMATION_REQUIRED]
operation=git_push
push_blocked=true
risk=high
blocked_reasons:
- env_secrets_added
- out_of_scope_db_config
- variable_logs_remaining
files:
- .github/workflows/deploy.yml:24
- src/db/client.ts:8
- prisma/schema.prisma
- package.json
- src/api/users.ts:18
required_user_confirmations:
1. GitHub Secrets / Environment Secrets を設定済みですか？
2. .env.example を更新済みですか？
3. scope外DB/config変更をこのPRに含める必要がありますか？
4. 変数logを削除、または残す理由を書きましたか？
5. 今回の変更に関係するテストまたは手動確認を行いましたか？
agent_instruction:
- Do not run git push again.
- Do not bypass hooks.
- Ask the user the required_user_confirmations.
- If the user confirms, explain the remaining risk before suggesting next action.
[/DEVGUARD_AGENT_CONFIRMATION_REQUIRED]
```

AI agents should read this block, ask the user for confirmations, and avoid retrying push or bypassing hooks without explicit user direction.

## 14. Implementation Phases

### Phase 0: Initialization

- Initialize package.
- Configure TypeScript.
- Configure Vitest.
- Create CLI entry point.

### Phase 1: Root Detection

- `runGit()`
- `detectRoot()`
- `normalizePath()`
- `toRootRelativePath()`
- `resolveConfigPath()`
- `devguard doctor`

### Phase 2: Diff Acquisition

- `getStagedFiles()`
- `getStagedDiff()`
- `getDefaultBranchDiff()`
- `parseNameStatus()`
- `parseDiffLines()`

### Phase 3: Preset and Config

- `loadConfig()`
- `validateConfig()`
- `loadEnabledPresets()`
- `mergeDefaultKeywordDatabase()`

### Phase 4: `check --staged`

- `classifyFiles()`
- keyword rule detection
- log policy detection
- suppression comment detection
- `applySuppressions()`
- `resolveTestCommands()`
- `generateChecklist()`
- `detectRisk()`
- `suggestCommitPlan()`
- CLI output for `devguard check --staged`

### Phase 5: `push-check`

- `envConsistencyCheck()`
- `issueScopeCheck()`
- strict log aggregation
- todo generation
- agent block generation
- CLI output for `devguard push-check`

### Phase 6: Hook Installation

- Install `pre-commit`.
- Install `pre-push`.
- Do not overwrite existing hooks silently.

## 15. Test Plan

### Test Categories

- Unit tests
- Config tests
- Fixture tests
- Integration tests
- Hook tests
- CLI E2E tests
- Snapshot tests

### Root Detection Tests

- `R-001`: Running at repository root resolves Git root.
- `R-002`: Running one level below resolves the same Git root.
- `R-003`: Running three levels below resolves the same Git root.
- `R-005`: `.devguard.yml` at root is detected.
- `R-006`: Missing `.devguard.yml` uses default config.
- `R-009`: Running outside Git exits with error.
- `R-014`: Windows-style paths normalize to `/`.
- `R-018`: Changing cwd does not change root detection invariants.

### Push Check Tests

- `P-001`: Environment variable addition blocks push.
- `P-002`: GitHub Actions secret reference blocks push.
- `P-003`: Missing `.env.example` update blocks push.
- `P-004`: Out-of-scope DB change blocks push.
- `P-005`: Out-of-scope config change blocks push.
- `P-006`: Remaining variable log blocks push.
- `P-007`: Static logs only produce Medium risk and allow push.
- `P-008`: AI-agent confirmation block is emitted.
- `P-009`: Todo list includes file paths.

### Hook Tests

- Low-risk change allows commit.
- Medium-risk change allows commit with warning.
- High-risk change blocks commit.
- Environment/secrets addition blocks push.
- Out-of-scope DB/config change blocks push.
- Remaining variable log blocks push.
- `--no-verify` can bypass hooks because Git allows it.

## 16. Recommended Build Order

Build in this order:

1. `doctor`
2. Root detection
3. Config loading
4. Staged diff acquisition
5. `defaultBranch...HEAD` diff acquisition
6. `logPolicy` and `keywordRules`
7. `envConsistencyCheck`
8. `issueScopeCheck`
9. `push-check`
10. Hook installation

The MVP should prioritize reliably stopping the user's most common misses over broad framework coverage.
