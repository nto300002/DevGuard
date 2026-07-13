import { execFile } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import type { ChangedFile, DiffLine } from "../src/git-diff.js";
import {
  applySuppressions,
  classifyFiles,
  evaluateDiffSize,
  detectKeywordFindings,
  detectLogFindings,
  detectRisk,
  formatDiffSizeWarning,
  generateChecklist,
  parseSuppressionComments,
  resolveTestCommands,
  suggestCommitPlan,
} from "../src/staged-check.js";

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = path.join(repoRoot, "src", "cli.ts");
const tsxBin = path.join(repoRoot, "node_modules", ".bin", "tsx");

async function git(cwd: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync("git", args, { cwd });
  return stdout;
}

async function createRepo(): Promise<string> {
  const repo = await mkdtemp(path.join(os.tmpdir(), "devguard-staged-check-"));
  await git(repo, ["init", "-b", "main"]);
  await git(repo, ["config", "user.name", "DevGuard Test"]);
  await git(repo, ["config", "user.email", "devguard@example.com"]);
  await writeFile(path.join(repo, "README.md"), "# Test\n");
  await git(repo, ["add", "README.md"]);
  await git(repo, ["commit", "-m", "initial"]);
  return repo;
}

function added(filePath: string, lineNumber: number, content: string): DiffLine {
  return { type: "added", filePath, lineNumber, content };
}

describe("staged check units", () => {
  it("classifies representative files", () => {
    const files: ChangedFile[] = [
      { status: "modified", path: "src/components/Button.tsx" },
      { status: "modified", path: "components/Header.tsx" },
      { status: "modified", path: "app/page.tsx" },
      { status: "modified", path: "app/dashboard/layout.tsx" },
      { status: "modified", path: "app/(marketing)/page.tsx" },
      { status: "modified", path: "app/blog/_components/Post.tsx" },
      { status: "modified", path: "src/app/settings/page.tsx" },
      { status: "modified", path: "pages/index.tsx" },
      { status: "modified", path: "src/pages/account.tsx" },
      { status: "modified", path: "src/App.tsx" },
      { status: "modified", path: "src/main.tsx" },
      { status: "modified", path: "app/api/users/route.ts" },
      { status: "modified", path: "prisma/schema.prisma" },
      { status: "modified", path: "package.json" },
      { status: "modified", path: "tests/unit.test.ts" },
    ];

    expect(classifyFiles(files)).toEqual({
      frontend: [
        "src/components/Button.tsx",
        "components/Header.tsx",
        "app/page.tsx",
        "app/dashboard/layout.tsx",
        "app/(marketing)/page.tsx",
        "app/blog/_components/Post.tsx",
        "src/app/settings/page.tsx",
        "pages/index.tsx",
        "src/pages/account.tsx",
        "src/App.tsx",
        "src/main.tsx",
      ],
      backend: ["app/api/users/route.ts"],
      db: ["prisma/schema.prisma"],
      config: ["package.json"],
      test: ["tests/unit.test.ts"],
      docs: [],
      unknown: [],
    });
  });

  it("detects keyword findings", () => {
    const findings = detectKeywordFindings([added("src/config.ts", 1, "const key = process.env.API_KEY;")]);

    expect(findings).toContainEqual(
      expect.objectContaining({
        ruleId: "secrets-credentials",
        severity: "high",
        filePath: "src/config.ts",
        lineNumber: 1,
      }),
    );
  });

  it("detects browser storage usage as a keyword risk", () => {
    const findings = detectKeywordFindings([
      added("app/page.tsx", 1, 'localStorage.setItem("theme", "dark");'),
      added("src/components/Panel.tsx", 2, 'sessionStorage.setItem("panel", "open");'),
    ]);

    expect(findings).toEqual([
      expect.objectContaining({
        ruleId: "browser-storage-risk",
        severity: "medium",
        filePath: "app/page.tsx",
        lineNumber: 1,
      }),
      expect.objectContaining({
        ruleId: "browser-storage-risk",
        severity: "medium",
        filePath: "src/components/Panel.tsx",
        lineNumber: 2,
      }),
    ]);
  });

  it("detects TypeScript and TSX risk keywords in Next.js and React files", () => {
    const findings = detectKeywordFindings([
      added("src/app/settings/page.tsx", 1, "return <div dangerouslySetInnerHTML={{ __html: html }} />;"),
      added("src/components/Button.tsx", 2, "const value = process.env.NEXT_PUBLIC_SECRET;"),
      added("src/hooks/useStorage.ts", 3, "window.localStorage.getItem(key);"),
    ]);

    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ruleId: "dangerous-apis",
          severity: "high",
          filePath: "src/app/settings/page.tsx",
          lineNumber: 1,
        }),
        expect.objectContaining({
          ruleId: "secrets-credentials",
          severity: "high",
          filePath: "src/components/Button.tsx",
          lineNumber: 2,
        }),
        expect.objectContaining({
          ruleId: "browser-storage-risk",
          severity: "medium",
          filePath: "src/hooks/useStorage.ts",
          lineNumber: 3,
        }),
      ]),
    );
  });

  it("categorizes strict log findings", () => {
    const findings = detectLogFindings([
      added("src/static.ts", 1, 'console.log("loaded");'),
      added("src/variable.ts", 2, "console.log(user);"),
      added("src/debug.ts", 3, "logger.debug(response);"),
      added("app/main.py", 4, "print(user)"),
      added("src/token.ts", 5, "console.log(token);"),
    ]);

    expect(findings.map((finding) => [finding.kind, finding.severity, finding.argumentKind])).toEqual([
      ["static-log", "medium", "static"],
      ["variable-log", "high", "variable"],
      ["logger-debug", "high", "variable"],
      ["print-variable", "high", "variable"],
      ["sensitive-log", "high", "sensitive"],
    ]);
  });

  it("applies suppression comments only when a reason exists", () => {
    const lines = [
      added("src/debug.ts", 1, "// devguard-disable-next-line variable-log -- CLI verbose debug output"),
      added("src/debug.ts", 2, "console.log(debugInfo);"),
      added("src/no-reason.ts", 1, "// devguard-disable-next-line variable-log"),
      added("src/no-reason.ts", 2, "console.log(debugInfo);"),
    ];

    const suppressions = parseSuppressionComments(lines);
    const findings = applySuppressions(detectLogFindings(lines), suppressions);

    expect(findings[0]).toMatchObject({
      suppressed: true,
      suppressionReason: "CLI verbose debug output",
    });
    expect(findings[1]).toMatchObject({
      suppressed: false,
    });
  });

  it("detects Low, Medium, and High risk", () => {
    expect(detectRisk([]).level).toBe("low");
    expect(detectRisk([{ severity: "medium", suppressed: false }]).level).toBe("medium");
    expect(detectRisk([{ severity: "high", suppressed: false }]).level).toBe("high");
    expect(detectRisk([{ severity: "high", suppressed: true }]).level).toBe("low");
  });

  it("generates tests, checklist, and commit plan", () => {
    const classified = classifyFiles([
      { status: "modified", path: "src/components/Button.tsx" },
      { status: "modified", path: "services/users.py" },
    ]);

    expect(resolveTestCommands(classified).map((item) => item.command)).toEqual(expect.arrayContaining(["npm run typecheck", "npm test", "pytest"]));
    expect(generateChecklist(classified).map((item) => item.label)).toContain("Changed screen was opened.");
    expect(suggestCommitPlan(classified).map((item) => item.title)).toEqual(["Frontend changes", "Backend changes"]);
  });

  it("evaluates staged diff size and recommends smaller PRs with concrete thresholds", () => {
    const files: ChangedFile[] = Array.from({ length: 6 }, (_, index) => ({
      status: "modified",
      path: `src/file-${index}.ts`,
    }));
    const lines: DiffLine[] = Array.from({ length: 151 }, (_, index) => added("src/file-0.ts", index + 1, `const value${index} = ${index};`));

    const summary = evaluateDiffSize(files, lines);

    expect(summary).toEqual({
      fileCount: 6,
      addedLineCount: 151,
      removedLineCount: 0,
      changedLineCount: 151,
      level: "medium",
      warning: "Staged diff is getting large. Consider splitting this work into smaller PRs.",
    });
    expect(formatDiffSizeWarning(summary)).toContain("1-5 files / <=150 changed lines: compact PR");
    expect(formatDiffSizeWarning(summary)).toContain("6-10 files or 151-300 changed lines: consider splitting");
    expect(formatDiffSizeWarning(summary)).toContain("11+ files or 301+ changed lines: split into smaller PRs");
  });
});

describe("devguard check --staged", () => {
  it("returns exit code 1 and prints High risk output for variable logs", async () => {
    const repo = await createRepo();
    await mkdir(path.join(repo, "src"), { recursive: true });
    await writeFile(path.join(repo, "src", "debug.ts"), "console.log(user);\n");
    await git(repo, ["add", "src/debug.ts"]);

    await expect(execFileAsync(tsxBin, [cliPath, "check", "--staged"], { cwd: repo })).rejects.toMatchObject({
      code: 1,
      stdout: expect.stringContaining("Risk: high"),
    });
  });

  it("returns exit code 0 and prints Medium risk output for static logs", async () => {
    const repo = await createRepo();
    await mkdir(path.join(repo, "src"), { recursive: true });
    await writeFile(path.join(repo, "src", "static.ts"), 'console.log("loaded");\n');
    await git(repo, ["add", "src/static.ts"]);

    const { stdout } = await execFileAsync(tsxBin, [cliPath, "check", "--staged"], { cwd: repo });

    expect(stdout).toContain("Risk: medium");
    expect(stdout).toContain("Recommended tests:");
    expect(stdout).toContain("Human checklist:");
  });

  it("supports check --staged-diff and warns when the staged diff is large", async () => {
    const repo = await createRepo();
    await mkdir(path.join(repo, "src"), { recursive: true });
    for (let index = 0; index < 6; index += 1) {
      await writeFile(path.join(repo, "src", `file-${index}.ts`), Array.from({ length: 26 }, (_, line) => `export const value${line} = ${line};`).join("\n"));
    }
    await git(repo, ["add", "src"]);

    const { stdout } = await execFileAsync(tsxBin, [cliPath, "check", "--staged-diff"], { cwd: repo });

    expect(stdout).toContain("DevGuard check --staged-diff");
    expect(stdout).toContain("Diff size:");
    expect(stdout).toContain("- files: 6");
    expect(stdout).toContain("- changed lines: 156");
    expect(stdout).toContain("Consider splitting this work into smaller PRs.");
    expect(stdout).toContain("11+ files or 301+ changed lines: split into smaller PRs");
  });

  it("supports check --worktree-diff for unstaged and untracked changes", async () => {
    const repo = await createRepo();
    await mkdir(path.join(repo, "src"), { recursive: true });
    await writeFile(path.join(repo, "src", "worktree.ts"), "console.log(user);\n");

    await expect(execFileAsync(tsxBin, [cliPath, "check", "--worktree-diff"], { cwd: repo })).rejects.toMatchObject({
      code: 1,
      stdout: expect.stringContaining("DevGuard check --worktree-diff"),
    });
  });

  it("supports check --all-diff for staged and unstaged changes", async () => {
    const repo = await createRepo();
    await mkdir(path.join(repo, "src"), { recursive: true });
    await writeFile(path.join(repo, "src", "staged.ts"), "localStorage.getItem(key);\n");
    await git(repo, ["add", "src/staged.ts"]);
    await writeFile(path.join(repo, "src", "unstaged.ts"), "sessionStorage.getItem(key);\n");

    const { stdout } = await execFileAsync(tsxBin, [cliPath, "check", "--all-diff"], { cwd: repo });

    expect(stdout).toContain("DevGuard check --all-diff");
    expect(stdout).toContain("src/staged.ts (added)");
    expect(stdout).toContain("src/unstaged.ts (added)");
    expect(stdout).toContain("Browser storage usage");
  });
});
