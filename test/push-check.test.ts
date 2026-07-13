import { execFile } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import type { ChangedFile, DiffLine } from "../src/git-diff.js";
import {
  envConsistencyCheck,
  generateAgentBlock,
  generatePushTodos,
  issueScopeCheck,
  runPushCheck,
} from "../src/push-check.js";

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = path.join(repoRoot, "src", "cli.ts");
const tsxBin = path.join(repoRoot, "node_modules", ".bin", "tsx");

async function git(cwd: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync("git", args, { cwd });
  return stdout;
}

async function createRepo(): Promise<string> {
  const repo = await mkdtemp(path.join(os.tmpdir(), "devguard-push-check-"));
  await git(repo, ["init", "-b", "main"]);
  await git(repo, ["config", "user.name", "DevGuard Test"]);
  await git(repo, ["config", "user.email", "devguard@example.com"]);
  await writeFile(path.join(repo, "README.md"), "# Test\n");
  await writeFile(path.join(repo, ".env.example"), "EXISTING_KEY=\n");
  await git(repo, ["add", "README.md", ".env.example"]);
  await git(repo, ["commit", "-m", "initial"]);
  await git(repo, ["switch", "-c", "feature"]);
  return repo;
}

function added(filePath: string, lineNumber: number, content: string): DiffLine {
  return { type: "added", filePath, lineNumber, content };
}

describe("envConsistencyCheck", () => {
  it("detects new env and GitHub secrets references", () => {
    const findings = envConsistencyCheck([
      added("src/db.ts", 1, "const url = process.env.DATABASE_URL;"),
      added(".github/workflows/deploy.yml", 2, "token: ${{ secrets.STRIPE_SECRET_KEY }}"),
    ]);

    expect(findings).toEqual([
      expect.objectContaining({
        name: "DATABASE_URL",
        source: "process.env",
        filePath: "src/db.ts",
        missingEnvExample: true,
      }),
      expect.objectContaining({
        name: "STRIPE_SECRET_KEY",
        source: "github.secrets",
        filePath: ".github/workflows/deploy.yml",
        missingEnvExample: true,
      }),
    ]);
  });

  it("does not mark env example missing when the key is added", () => {
    const findings = envConsistencyCheck([added("src/db.ts", 1, "process.env.DATABASE_URL"), added(".env.example", 1, "DATABASE_URL=")]);

    expect(findings[0]).toMatchObject({
      name: "DATABASE_URL",
      missingEnvExample: false,
    });
  });
});

describe("issueScopeCheck", () => {
  it("detects DB and config changes outside frontend scope", () => {
    const findings = issueScopeCheck(
      [
        { status: "modified", path: "src/components/Button.tsx" },
        { status: "modified", path: "prisma/schema.prisma" },
        { status: "modified", path: "package.json" },
      ] satisfies ChangedFile[],
      "frontend",
    );

    expect(findings).toEqual([
      { filePath: "prisma/schema.prisma", category: "db", scope: "frontend" },
      { filePath: "package.json", category: "config", scope: "frontend" },
    ]);
  });
});

describe("push todo and agent block generation", () => {
  it("generates todos and an agent block with blocked reasons", () => {
    const todos = generatePushTodos({
      envFindings: [{ name: "DATABASE_URL", source: "process.env", filePath: "src/db.ts", lineNumber: 1, missingEnvExample: true }],
      scopeFindings: [{ filePath: "package.json", category: "config", scope: "frontend" }],
      logFindings: [{ filePath: "src/debug.ts", lineNumber: 4, kind: "variable-log" }],
    });
    const block = generateAgentBlock({
      blockedReasons: ["env_secrets_added", "out_of_scope_db_config", "personal_strict_variable_log"],
      files: ["src/db.ts:1", "package.json", "src/debug.ts:4"],
      todos,
    });

    expect(todos.map((todo) => todo.category)).toEqual(expect.arrayContaining(["env", "scope", "log", "test"]));
    expect(block).toContain("[DEVGUARD_AGENT_CONFIRMATION_REQUIRED]");
    expect(block).toContain("env_secrets_added");
    expect(block).toContain("Do not run git push again.");
  });
});

describe("devguard push-check", () => {
  it("blocks env/secrets additions and emits an agent block", async () => {
    const repo = await createRepo();
    await mkdir(path.join(repo, "src"), { recursive: true });
    await writeFile(path.join(repo, "src", "db.ts"), "export const db = process.env.DATABASE_URL;\n");
    await git(repo, ["add", "src/db.ts"]);
    await git(repo, ["commit", "-m", "add env"]);

    const result = await runPushCheck(repo, { agentBlock: true });

    expect(result.pushAllowed).toBe(false);
    expect(result.blockedReasons).toContain("env_secrets_added");
    expect(result.agentBlock).toContain("required_user_confirmations");
  });

  it("returns exit code 1 for blocked CLI push-check", async () => {
    const repo = await createRepo();
    await mkdir(path.join(repo, "src"), { recursive: true });
    await writeFile(path.join(repo, "src", "debug.ts"), "console.log(user);\n");
    await git(repo, ["add", "src/debug.ts"]);
    await git(repo, ["commit", "-m", "add debug"]);

    await expect(execFileAsync(tsxBin, [cliPath, "push-check", "--agent-block"], { cwd: repo })).rejects.toMatchObject({
      code: 1,
      stdout: expect.stringContaining("Push: blocked"),
    });
  });

  it("returns exit code 0 for warning-only changes", async () => {
    const repo = await createRepo();
    await writeFile(path.join(repo, "README.md"), "# Test\nupdated\n");
    await git(repo, ["add", "README.md"]);
    await git(repo, ["commit", "-m", "docs update"]);

    const { stdout } = await execFileAsync(tsxBin, [cliPath, "push-check"], { cwd: repo });

    expect(stdout).toContain("Push: allowed");
  });
});
