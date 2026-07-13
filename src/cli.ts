#!/usr/bin/env node

import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runCheckStagedCommand } from "./staged-check.js";
import { formatHookInstallResult, installHooks } from "./hooks.js";
import { detectRoot, formatDoctorResult } from "./root.js";
import { runPushCheckCommand } from "./push-check.js";

const helpText = `DevGuard

Usage:
  devguard doctor
  devguard init
  devguard check --staged
  devguard check --staged-diff
  devguard check --worktree-diff
  devguard check --all-diff
  devguard push-check
  devguard install-hooks
  devguard --help

Pre-commit and pre-push self-review CLI for AI-assisted development.
`;

export function getHelpText(): string {
  return helpText;
}

export async function main(args = process.argv.slice(2)): Promise<number> {
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    process.stdout.write(getHelpText());
    return 0;
  }

  if (args[0] === "check" && (args[1] === "--staged" || args[1] === "--staged-diff" || args[1] === "--worktree-diff" || args[1] === "--all-diff")) {
    return runCheckStagedCommand(process.cwd(), {
      commandName: `check ${args[1]}`,
      diffScope: args[1] === "--worktree-diff" ? "worktree" : args[1] === "--all-diff" ? "all" : "staged",
    });
  }

  if (args[0] === "doctor") {
    const result = await detectRoot(process.cwd());
    process.stdout.write(formatDoctorResult(result));
    return 0;
  }

  if (args[0] === "install-hooks") {
    const root = await detectRoot(process.cwd());
    const result = await installHooks(root.gitRoot);
    process.stdout.write(formatHookInstallResult(result));
    return 0;
  }

  if (args[0] === "push-check") {
    const root = await detectRoot(process.cwd());
    const scopeIndex = args.indexOf("--scope");
    return runPushCheckCommand(root.gitRoot, {
      agentBlock: args.includes("--agent-block"),
      scope: scopeIndex >= 0 ? args[scopeIndex + 1] : undefined,
    });
  }

  process.stderr.write(`Unknown command: ${args.join(" ")}\n`);
  process.stderr.write("Run devguard --help for usage.\n");
  return 1;
}

export function isDirectCliExecution(moduleUrl: string, argvPath: string | undefined): boolean {
  if (!argvPath) {
    return false;
  }

  return realpathSync(fileURLToPath(moduleUrl)) === realpathSync(argvPath);
}

const isDirectExecution = isDirectCliExecution(import.meta.url, process.argv[1]);

if (isDirectExecution) {
  const exitCode = await main();
  process.exitCode = exitCode;
}
