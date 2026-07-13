import { access, chmod, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

export type HookName = "pre-commit" | "pre-push";

export type HookInstallResult = {
  installed: HookName[];
  skipped: Array<{
    hookName: HookName;
    reason: "already-exists";
  }>;
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

export async function installHooks(gitRoot: string): Promise<HookInstallResult> {
  const hooksDir = path.join(gitRoot, ".git", "hooks");
  await mkdir(hooksDir, { recursive: true });

  const result: HookInstallResult = {
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

export function formatHookInstallResult(result: HookInstallResult): string {
  const lines = ["DevGuard install-hooks"];

  if (result.installed.length > 0) {
    lines.push("Installed:");
    for (const hookName of result.installed) {
      lines.push(`- ${hookName}`);
    }
  }

  if (result.skipped.length > 0) {
    lines.push("Skipped:");
    for (const skipped of result.skipped) {
      lines.push(`- ${skipped.hookName} (${skipped.reason})`);
    }
  }

  if (result.installed.length === 0 && result.skipped.length === 0) {
    lines.push("No hooks changed.");
  }

  return `${lines.join("\n")}\n`;
}

async function exists(filePath: string): Promise<boolean> {
  return access(filePath)
    .then(() => true)
    .catch(() => false);
}
