#!/usr/bin/env node

import { runCheckStagedCommand } from "./staged-check.js";
import { formatHookInstallResult, installHooks } from "./hooks.js";
import { detectRoot, formatDoctorResult } from "./root.js";

const helpText = `DevGuard

Usage:
  devguard doctor
  devguard init
  devguard check --staged
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

  if (args[0] === "check" && args[1] === "--staged") {
    return runCheckStagedCommand(process.cwd());
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

  process.stderr.write(`Unknown command: ${args.join(" ")}\n`);
  process.stderr.write("Run devguard --help for usage.\n");
  return 1;
}

const isDirectExecution = import.meta.url === `file://${process.argv[1]}`;

if (isDirectExecution) {
  const exitCode = await main();
  process.exitCode = exitCode;
}
