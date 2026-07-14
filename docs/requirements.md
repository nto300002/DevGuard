# DevGuard Requirements

## 1. Product Overview

### Product Name

DevGuard

### README Description

DevGuard is a Git hook based CLI tool that automatically diagnoses changes before commit and push. It helps prevent review misses that often happen during AI-assisted coding or ADHD-prone development workflows, including overlooked change scope, overly broad commit units, forgotten debug logs, missing environment or secrets confirmation, and insufficient manual checks before review.

DevGuard classifies changed files, identifies risk, suggests commit splits, generates pre-push todos, and emits confirmation blocks that AI coding agents can read before attempting a push.

## 2. Problems To Solve

DevGuard focuses on process-level review misses, not only code quality.

The personal MVP prioritizes the following problems:

- Commit units become too broad.
- AI-generated output is accepted without enough skepticism.
- `console.log`, `print`, `logger.debug`, and similar debug output is forgotten.
- GitHub Secrets and external environment variables are not checked.
- CI/CD environment setup is missed.
- DB or config changes outside the issue scope are mixed into a PR.
- Push happens before manual tests and confirmations are clear.

## 3. Product Concept

DevGuard is a pre-commit and pre-push self-review tool for the AI coding era.

It does not generate code. Its purpose is to make the developer pause before Git operations and reach a state where the change can be explained clearly.

For ADHD support, DevGuard externalizes important checks:

- Stop before commit.
- Stop before push.
- Show changed scope.
- Aggregate forgotten logs.
- Convert environment and secrets checks into todos.
- Make out-of-scope changes visible.
- Ask AI agents to prompt the user before retrying push.

## 4. Target Users

### Initial Target

The initial target user is the project owner.

### Future Targets

- Beginner engineers using AI coding tools.
- Developers who are prone to confirmation misses due to ADHD traits.
- Engineers in disability employment contexts.
- Junior developers who want stable review readiness before asking for review.

## 5. MVP Scope

### Included

1. Git root auto-detection
2. Root-relative path normalization
3. `.devguard.yml` loading
4. `devguard doctor`
5. `devguard check --staged`
6. `devguard push-check`
7. `defaultBranch...HEAD` diff acquisition
8. `keywordRules`
9. `logPolicy` and `personalStrictLog`
10. Suppression comments
11. `envConsistencyCheck`
12. `issueScopeCheck`
13. Manual test confirmation todos
14. AI-agent confirmation blocks
15. `pre-commit` and `pre-push` hook installation

### Excluded

- GitHub OAuth integration
- Live GitHub Secrets existence checks
- GitHub Issue body fetching
- Web UI
- VS Code extension
- AI review features
- AI-generated code truth validation
- AST analysis
- Automatic fixes
- Interactive todo input
- Confirmation state persistence
- GitHub Actions integration
- AI-agent specific hook integration

## 6. Technology Requirements

- Implementation language: TypeScript + Node.js
- Test framework: Vitest
- Development approach: TDD, with failing tests written before production code for each implementation slice
- Runtime form: CLI tool
- Initial UI: command-line output

## 7. Core Commands

### `devguard doctor`

Displays root detection, config detection, and Git state.

Required output sections:

- Git
  - inside work tree
  - bare repository
  - git root
  - current directory
  - relative cwd
- Config
  - config path
  - config loaded
  - using default config
- Path
  - root-relative paths enabled
  - separator normalized to `/`

### `devguard check --staged`

Diagnoses staged changes before commit.

Required checks:

- staged files
- keyword rules
- strict log policy
- suppression comments
- recommended tests
- commit split suggestions
- human review checklist

### `devguard check --staged-diff`

Diagnoses staged changes before commit with explicit diff size guidance.

Required checks:

- staged file paths
- added line count
- removed line count
- changed line count
- PR size guidance

PR size guidance:

- 1-5ファイル / 変更150行以下: 小さくまとまったPR
- 6-10ファイル または 変更151-300行: PR分割を検討
- 11ファイル以上 または 変更301行以上: 小さなPRに分割

If the staged diff reaches 6 files or 151 changed lines, DevGuard should warn the user in Japanese to consider smaller PRs.
If the staged diff reaches 11 files or 301 changed lines, DevGuard should strongly recommend splitting the work before review in Japanese.

### `devguard check --worktree-diff`

Diagnoses unstaged and untracked worktree changes before staging.

Required checks:

- unstaged tracked file changes
- untracked text files
- keyword rules
- strict log policy
- diff size guidance

### `devguard check --all-diff`

Diagnoses all local changes compared with `HEAD`.

Required checks:

- staged changes
- unstaged tracked file changes
- untracked text files
- keyword rules
- strict log policy
- diff size guidance

Diff scope naming:

- `--staged`: staged changes only
- `--staged-diff`: staged changes with explicit size guidance
- `--worktree-diff`: unstaged and untracked worktree changes
- `--all-diff`: staged, unstaged, and untracked changes

### `devguard push-check`

Diagnoses branch-level changes before push.

Required checks:

- environment and secrets additions
- out-of-scope DB/config changes
- remaining variable logs under strict log policy
- manual test confirmation todos
- AI-agent confirmation block

### `devguard install-hooks`

Installs Git hooks for:

- `pre-commit`
- `pre-push`

Existing hooks must not be overwritten silently.
Hook directory resolution must use Git's own hook path so submodules and worktrees are supported.
When `--include-submodules` is provided, DevGuard should install the same hooks into the root repository and initialized recursive submodules.

### `devguard init`

Generates a `.devguard.yml` template.

## 8. Git Root Requirements

Git root is the base directory for all diagnostics.

Commands used for root detection:

```bash
git rev-parse --is-inside-work-tree
git rev-parse --is-bare-repository
git rev-parse --show-toplevel
```

Root detection result:

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

Invariant: running DevGuard from any subdirectory inside the same Git repository must produce the same `gitRoot`, the same config path, and the same root-relative diagnostics.

## 9. Path Normalization Requirements

Internally, all file paths must be normalized to:

- Git-root relative paths
- `/` separators

Example:

```text
src\components\Button.tsx
```

becomes:

```text
src/components/Button.tsx
```

Files outside the Git root must not be included in diagnostics.

## 10. Config Requirements

- Config file name: `.devguard.yml`
- Load location: `<git-root>/.devguard.yml`
- Missing config: continue with default config
- Invalid config: exit code `1`

Invalid config must not silently fall back to default config because doing so could allow commits or pushes without intended guardrails.

## 11. Default Config Shape

```yaml
project:
  name: "sample-app"
  defaultBranch: "main"

presets:
  enabled:
    - "typescript"
    - "nextjs"
    - "python"
    - "fastapi"
    - "php"

logPolicy:
  preset: "personalStrictLog"
  aggregate: true
  maxExamplesPerGroup: 3

pushCheck:
  enabled: true
  agentBlock: true
  blockOn:
    envSecretsAdded: true
    outOfScopeDbConfig: true
    personalStrictVariableLog: true

envConsistency:
  enabled: true
  requireEnvExampleUpdate: true

issueScope:
  enabled: true
  defaultMode: "warn"
  allowedScopes:
    frontend:
      paths:
        - "src/app/**"
        - "app/**"
        - "src/pages/**"
        - "pages/**"
        - "src/components/**"
        - "components/**"
    backend:
      paths:
        - "app/**"
        - "src/**"
        - "routers/**"
        - "routes/**"
        - "services/**"
        - "api/**"
    db:
      paths:
        - "prisma/**"
        - "migrations/**"
        - "alembic/**"
        - "database/**"
        - "db/**"
        - "models/**"
    config:
      paths:
        - "package.json"
        - "pnpm-lock.yaml"
        - "package-lock.json"
        - "tsconfig.json"
        - "next.config.*"
        - "requirements.txt"
        - "pyproject.toml"
        - "poetry.lock"
        - "composer.json"
        - "composer.lock"
        - ".github/workflows/**"
        - ".env.example"

testCommands:
  typecheck:
    command: "npm run typecheck"
  lint:
    command: "npm run lint"
  test:
    command: "npm test"
  python-test:
    command: "pytest"
  python-lint:
    command: "ruff check ."
  php-test:
    command: "composer test"
```

## 12. Supported MVP Technologies

MVP presets:

- TypeScript
- Python
- PHP
- Next.js
- FastAPI

MVP excludes first-class support for:

- JavaScript-only projects
- React-only projects
- Django
- Flutter
- Java
- C#
- Go
- .NET

The MVP should not deeply parse frameworks. It should detect representative directory structures, environment references, config and dependency changes, debug logs, DB or migration-like changes, recommended tests, and manual confirmation todos.

## 13. Diff Requirements

`push-check` uses:

```bash
git diff <defaultBranch>...HEAD
```

Default branch priority:

1. `.devguard.yml` `project.defaultBranch`
2. `main`
3. `master`

The MVP does not strictly parse pre-push standard input refs. It uses `defaultBranch...HEAD` first.

## 14. Hook Requirements

### Pre-commit

Command:

```bash
npx @nto300002/devguard check --staged
```

Targets:

- staged file paths
- staged added lines
- staged removed lines
- keyword rules
- log policy
- suppression comments
- recommended tests
- commit split suggestions

Exit codes:

| State | Exit Code | Behavior |
| --- | ---: | --- |
| Low | 0 | Commit passes |
| Medium | 0 | Warn and commit passes |
| High | 1 | Commit stops |
| Invalid config | 1 | Commit stops |
| Internal error | 2 | Commit stops |

### Pre-push

Command:

```bash
npx @nto300002/devguard push-check --agent-block
```

Push blockers:

1. Environment or secrets additions
2. Out-of-scope DB/config changes
3. Remaining variable logs under `personalStrictLog`

Exit codes:

| State | Exit Code | Behavior |
| --- | ---: | --- |
| No issue | 0 | Push passes |
| Warning only | 0 | Push passes |
| Env/secrets addition | 1 | Push stops |
| Out-of-scope DB/config change | 1 | Push stops |
| Variable log remains | 1 | Push stops |
| Invalid config | 1 | Push stops |
| Internal error | 2 | Push stops |

## 15. Risk Requirements

Risk levels:

| Risk | Meaning |
| --- | --- |
| Low | Pass |
| Medium | Warn and pass |
| High | Stop commit or push |

Score guideline:

- `0-29`: Low
- `30-69`: Medium
- `70+`: High

High-risk push conditions:

- Environment or secrets added
- `.env.example` not updated
- Out-of-scope DB change
- Out-of-scope config change
- Variable logs remain under strict log policy
- Sensitive logs remain

## 16. MVP Completion Criteria

- `devguard doctor` works.
- Running from root and subdirectories detects the same Git root.
- `.devguard.yml` can be loaded.
- Missing config falls back to default config.
- `devguard check --staged` works.
- `personalStrictLog` detects variable logs.
- Suppression comments and reasons are handled.
- `devguard push-check` can inspect `defaultBranch...HEAD`.
- Environment/secrets additions stop push.
- Out-of-scope DB/config changes stop push.
- Remaining variable logs stop push.
- Confirmation todos are displayed as a todo list.
- AI-agent confirmation blocks are displayed.
- `pre-commit` and `pre-push` hooks can be installed.

## 17. Future Candidates

- JSON output
- Interactive todo input
- Confirmation token persistence
- GitHub Actions integration
- Live GitHub Secrets existence checks
- GitHub Issue body fetching
- VS Code extension
- AI-agent specific hooks
- AST analysis
- First-class JavaScript, React, Django, Flutter, Java, C#, Go, and .NET presets
