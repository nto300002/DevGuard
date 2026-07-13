import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rename, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import {
  getAllDiff,
  getDefaultBranchDiff,
  getStagedDiff,
  getStagedFiles,
  getWorktreeDiff,
  parseDiffLines,
  parseNameStatus,
} from "../src/git-diff.js";

const execFileAsync = promisify(execFile);

async function git(cwd: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync("git", args, { cwd });
  return stdout;
}

async function createRepo(): Promise<string> {
  const repo = await mkdtemp(path.join(os.tmpdir(), "devguard-git-diff-"));
  await git(repo, ["init", "-b", "main"]);
  await git(repo, ["config", "user.name", "DevGuard Test"]);
  await git(repo, ["config", "user.email", "devguard@example.com"]);
  await writeFile(path.join(repo, "README.md"), "# Test\n");
  await git(repo, ["add", "README.md"]);
  await git(repo, ["commit", "-m", "initial"]);
  return repo;
}

describe("parseNameStatus", () => {
  it("parses added, modified, deleted, and renamed files", () => {
    const files = parseNameStatus(["A\tsrc/new.ts", "M\tsrc/existing.ts", "D\tsrc/old.ts", "R100\tsrc/from.ts\tsrc/to.ts"].join("\n"));

    expect(files).toEqual([
      { status: "added", path: "src/new.ts" },
      { status: "modified", path: "src/existing.ts" },
      { status: "deleted", path: "src/old.ts" },
      { status: "renamed", path: "src/to.ts", previousPath: "src/from.ts" },
    ]);
  });

  it("normalizes Windows-style separators", () => {
    const files = parseNameStatus("A\tsrc\\components\\Button.tsx");

    expect(files[0]?.path).toBe("src/components/Button.tsx");
  });
});

describe("parseDiffLines", () => {
  it("parses added and removed lines with file path and line number", () => {
    const diff = [
      "diff --git a/src/app.ts b/src/app.ts",
      "index 1111111..2222222 100644",
      "--- a/src/app.ts",
      "+++ b/src/app.ts",
      "@@ -2,2 +2,3 @@",
      " keep();",
      "-oldValue();",
      "+newValue();",
      "+console.log(user);",
    ].join("\n");

    expect(parseDiffLines(diff)).toEqual([
      {
        type: "removed",
        filePath: "src/app.ts",
        lineNumber: 3,
        content: "oldValue();",
      },
      {
        type: "added",
        filePath: "src/app.ts",
        lineNumber: 3,
        content: "newValue();",
      },
      {
        type: "added",
        filePath: "src/app.ts",
        lineNumber: 4,
        content: "console.log(user);",
      },
    ]);
  });

  it("parses deleted file lines against the old file path", () => {
    const diff = ["diff --git a/src/old.ts b/src/old.ts", "deleted file mode 100644", "--- a/src/old.ts", "+++ /dev/null", "@@ -1 +0,0 @@", "-old();"].join("\n");

    expect(parseDiffLines(diff)).toEqual([
      {
        type: "removed",
        filePath: "src/old.ts",
        lineNumber: 1,
        content: "old();",
      },
    ]);
  });
});

describe("git diff collection", () => {
  it("collects staged files and staged diff lines", async () => {
    const repo = await createRepo();
    await mkdir(path.join(repo, "src"), { recursive: true });
    await writeFile(path.join(repo, "src", "old.ts"), "old();\n");
    await writeFile(path.join(repo, "src", "before.ts"), "before();\n");
    await git(repo, ["add", "src/old.ts", "src/before.ts"]);
    await git(repo, ["commit", "-m", "add files to change"]);

    await writeFile(path.join(repo, "src", "new.ts"), "console.log(user);\n");
    await writeFile(path.join(repo, "README.md"), "# Test\nupdated\n");
    await rename(path.join(repo, "src", "before.ts"), path.join(repo, "src", "after.ts"));
    await git(repo, ["rm", "src/old.ts"]);
    await git(repo, ["add", "-A"]);

    const stagedFiles = await getStagedFiles(repo);
    const stagedDiff = await getStagedDiff(repo);

    expect(stagedFiles).toEqual([
      { status: "modified", path: "README.md" },
      { status: "renamed", path: "src/after.ts", previousPath: "src/before.ts" },
      { status: "added", path: "src/new.ts" },
      { status: "deleted", path: "src/old.ts" },
    ]);
    expect(stagedDiff.files).toEqual(stagedFiles);
    expect(stagedDiff.lines).toContainEqual({
      type: "added",
      filePath: "src/new.ts",
      lineNumber: 1,
      content: "console.log(user);",
    });
  });

  it("collects defaultBranch...HEAD diff lines", async () => {
    const repo = await createRepo();
    await git(repo, ["switch", "-c", "feature"]);
    await mkdir(path.join(repo, "src"), { recursive: true });
    await writeFile(path.join(repo, "src", "before.ts"), "before();\n");
    await git(repo, ["add", "src/before.ts"]);
    await git(repo, ["commit", "-m", "add before"]);
    await rename(path.join(repo, "src", "before.ts"), path.join(repo, "src", "after.ts"));
    await writeFile(path.join(repo, "src", "after.ts"), "after();\n");
    await git(repo, ["add", "-A"]);
    await git(repo, ["commit", "-m", "rename file"]);

    const branchDiff = await getDefaultBranchDiff(repo, "main");

    expect(branchDiff.files).toEqual([{ status: "added", path: "src/after.ts" }]);
    expect(branchDiff.lines).toContainEqual({
      type: "added",
      filePath: "src/after.ts",
      lineNumber: 1,
      content: "after();",
    });
  });

  it("collects unstaged and untracked worktree diff lines", async () => {
    const repo = await createRepo();
    await mkdir(path.join(repo, "src"), { recursive: true });
    await writeFile(path.join(repo, "src", "tracked.ts"), "before();\n");
    await git(repo, ["add", "src/tracked.ts"]);
    await git(repo, ["commit", "-m", "add tracked"]);

    await writeFile(path.join(repo, "src", "tracked.ts"), "before();\nafter();\n");
    await writeFile(path.join(repo, "src", "untracked.ts"), "console.log(user);\n");

    const worktreeDiff = await getWorktreeDiff(repo);

    expect(worktreeDiff.files).toEqual([
      { status: "modified", path: "src/tracked.ts" },
      { status: "added", path: "src/untracked.ts" },
    ]);
    expect(worktreeDiff.lines).toEqual(
      expect.arrayContaining([
        {
          type: "added",
          filePath: "src/tracked.ts",
          lineNumber: 2,
          content: "after();",
        },
        {
          type: "added",
          filePath: "src/untracked.ts",
          lineNumber: 1,
          content: "console.log(user);",
        },
      ]),
    );
  });

  it("collects staged, unstaged, and untracked lines for all diff", async () => {
    const repo = await createRepo();
    await mkdir(path.join(repo, "src"), { recursive: true });
    await writeFile(path.join(repo, "src", "tracked.ts"), "before();\n");
    await git(repo, ["add", "src/tracked.ts"]);
    await git(repo, ["commit", "-m", "add tracked"]);

    await writeFile(path.join(repo, "src", "staged.ts"), "localStorage.getItem(key);\n");
    await git(repo, ["add", "src/staged.ts"]);
    await writeFile(path.join(repo, "src", "tracked.ts"), "before();\nafter();\n");
    await writeFile(path.join(repo, "src", "untracked.ts"), "sessionStorage.getItem(key);\n");

    const allDiff = await getAllDiff(repo);

    expect(allDiff.files).toEqual([
      { status: "added", path: "src/staged.ts" },
      { status: "modified", path: "src/tracked.ts" },
      { status: "added", path: "src/untracked.ts" },
    ]);
    expect(allDiff.lines.map((line) => `${line.filePath}:${line.content}`)).toEqual(
      expect.arrayContaining([
        "src/staged.ts:localStorage.getItem(key);",
        "src/tracked.ts:after();",
        "src/untracked.ts:sessionStorage.getItem(key);",
      ]),
    );
  });
});
