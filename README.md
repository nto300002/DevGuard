# DevGuard

DevGuard is a TypeScript + Node.js CLI tool that helps developers stop and review risky changes before `git commit` and `git push`.

It is designed for AI-assisted development and ADHD-friendly workflows where the common failure mode is not only code quality, but missed confirmation steps: broad commits, forgotten debug logs, missing environment variable updates, out-of-scope DB/config changes, and vague pre-review checks.

## Concept

DevGuard is a pre-commit and pre-push self-review assistant for the AI coding era.

It does not write code like Copilot and it does not replace a reviewer. Instead, it analyzes Git diffs immediately before Git operations and makes the developer explain what changed, what is risky, and what still needs human confirmation.

## MVP Scope

The MVP focuses on:

- Git root detection from any subdirectory
- Root-relative path normalization
- `.devguard.yml` loading with safe defaults
- `devguard doctor`
- `devguard check --staged`
- `devguard push-check`
- `defaultBranch...HEAD` diff analysis
- Keyword rules
- Strict debug-log detection
- Suppression comments with required reasons
- Environment and secrets consistency checks
- Issue scope checks
- Manual test confirmation todos
- AI-agent confirmation blocks
- `pre-commit` and `pre-push` hook installation

The MVP intentionally excludes GitHub OAuth, live GitHub Secrets verification, GitHub Issue body fetching, Web UI, VS Code extensions, AST analysis, automatic fixes, and AI code correctness judgment.

## Target Technologies

Initial presets:

- TypeScript
- Python
- PHP
- Next.js
- FastAPI

Other ecosystems may appear in the default keyword database, but they are not enabled as first-class MVP presets.

## Commands

```bash
devguard doctor
devguard init
devguard check --staged
devguard push-check
devguard install-hooks
```

## Hook Behavior

`pre-commit` runs:

```bash
npx devguard check --staged
```

`pre-push` runs:

```bash
npx devguard push-check --agent-block
```

High-risk commit findings stop the commit. High-risk push findings stop the push.

## Documentation

- [Requirements](docs/requirements.md)
- [Detailed Design](docs/detail-design.md)

## MVP Completion Criteria

The MVP is complete when DevGuard can reliably detect risky logs, environment/secrets additions, and out-of-scope DB/config changes for TypeScript, Python, PHP, Next.js, and FastAPI projects before commit or push.
