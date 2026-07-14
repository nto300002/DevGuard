import { access, chmod, mkdir, realpath, writeFile } from "node:fs/promises";
import path from "node:path";
import { runGit } from "./root.js";

export type HookName = "pre-commit" | "pre-push";

export type HookInstallRepositoryResult = {
  gitRoot: string;
  installed: HookName[];
  skipped: Array<{
    hookName: HookName;
    reason: "already-exists";
  }>;
};

export type HookInstallResult = {
  installed: HookName[];
  skipped: Array<{
    hookName: HookName;
    reason: "already-exists";
  }>;
  repositories: HookInstallRepositoryResult[];
};

export type HookInstallOptions = {
  includeSubmodules?: boolean;
};

const HOOKS: Record<HookName, string> = {
  "pre-commit": `#!/bin/sh
set -e

DEVGUARD_BIN="\${DEVGUARD_BIN:-npx @nto300002/devguard}"
$DEVGUARD_BIN check --staged
`,
  "pre-push": `#!/bin/sh
set -e

DEVGUARD_BIN="\${DEVGUARD_BIN:-npx @nto300002/devguard}"
$DEVGUARD_BIN push-check --agent-block
`,
};

export async function installHooks(gitRoot: string, options: HookInstallOptions = {}): Promise<HookInstallResult> {
  const normalizedGitRoot = await realpath(gitRoot);
  const repositories = [await installHooksInRepository(normalizedGitRoot)];

  if (options.includeSubmodules) {
    for (const submoduleRoot of await listInitializedSubmoduleRoots(normalizedGitRoot)) {
      repositories.push(await installHooksInRepository(submoduleRoot));
    }
  }

  return {
    installed: repositories.flatMap((repository) => repository.installed),
    skipped: repositories.flatMap((repository) => repository.skipped),
    repositories,
  };
}

async function installHooksInRepository(gitRoot: string): Promise<HookInstallRepositoryResult> {
  const hooksDir = await resolveHooksDir(gitRoot);
  await mkdir(hooksDir, { recursive: true });

  const result: HookInstallRepositoryResult = {
    gitRoot,
    installed: [],
    skipped: [],
  };

  for (const hookName of Object.keys(HOOKS) as HookName[]) {
    const hookPath = path.join(hooksDir, hookName);
    if (await exists(hookPath)) {
      result.skipped.push({ hookName, reason: "already-exists" });
      continue;
    }

    await writeFile(hookPath, HOOKS[hookName], { mode: 0o755 });
    await chmod(hookPath, 0o755);
    result.installed.push(hookName);
  }

  return result;
}

async function resolveHooksDir(gitRoot: string): Promise<string> {
  const hooksPath = await runGit(gitRoot, ["rev-parse", "--git-path", "hooks"]);
  return path.isAbsolute(hooksPath) ? hooksPath : path.resolve(gitRoot, hooksPath);
}

async function listInitializedSubmoduleRoots(gitRoot: string): Promise<string[]> {
  const stdout = await runGit(gitRoot, ["submodule", "foreach", "--recursive", "--quiet", "pwd"]);
  const roots = await Promise.all(
    stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((submoduleRoot) => realpath(submoduleRoot)),
  );
  return roots
    .filter((submoduleRoot, index) => roots.indexOf(submoduleRoot) === index);
}

export function formatHookInstallResult(result: HookInstallResult): string {
  const lines = ["DevGuard install-hooks"];
  const repositories = result.repositories ?? [];

  if (repositories.length > 1) {
    lines.push("対象リポジトリ:");
    for (const repository of repositories) {
      lines.push(`- ${repository.gitRoot}`);
      if (repository.installed.length > 0) {
        lines.push(`  インストール済み: ${repository.installed.join(", ")}`);
      }
      if (repository.skipped.length > 0) {
        lines.push(`  スキップ: ${repository.skipped.map((skipped) => `${skipped.hookName} (${formatSkipReason(skipped.reason)})`).join(", ")}`);
      }
    }
    return `${lines.join("\n")}\n`;
  }

  if (result.installed.length > 0) {
    lines.push("インストール済み:");
    for (const hookName of result.installed) {
      lines.push(`- ${hookName}`);
    }
  }

  if (result.skipped.length > 0) {
    lines.push("スキップ:");
    for (const skipped of result.skipped) {
      lines.push(`- ${skipped.hookName} (${formatSkipReason(skipped.reason)})`);
    }
  }

  if (result.installed.length === 0 && result.skipped.length === 0) {
    lines.push("変更されたhookはありません。");
  }

  return `${lines.join("\n")}\n`;
}

function formatSkipReason(reason: "already-exists"): string {
  if (reason === "already-exists") {
    return "既に存在";
  }
  return reason;
}

async function exists(filePath: string): Promise<boolean> {
  return access(filePath)
    .then(() => true)
    .catch(() => false);
}
