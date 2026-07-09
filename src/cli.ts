#!/usr/bin/env node

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

  process.stderr.write(`Unknown command: ${args.join(" ")}\n`);
  process.stderr.write("Run devguard --help for usage.\n");
  return 1;
}

const isDirectExecution = import.meta.url === `file://${process.argv[1]}`;

if (isDirectExecution) {
  const exitCode = await main();
  process.exitCode = exitCode;
}
