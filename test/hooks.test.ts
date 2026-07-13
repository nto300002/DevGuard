import { execFile } from "node:child_process";
import { access, chmod, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { formatHookInstallResult, installHooks } from "../src/hooks.js";

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = path.join(repoRoot, "src", "cli.ts");
const tsxBin = path.join(repoRoot, "node_modules", ".bin", "tsx");

async function git(cwd: string, args: string[], env: NodeJS.ProcessEnv = {}): Promise<{ stdout: string; stderr: string }> {
  return execFileAsync("git", args, {
    cwd,
    env: { ...process.env, ...env },
  });
}

async function createRepo(): Promise<string> {
  const repo = await mkdtemp(path.join(os.tmpdir(), "devguard-hooks-"));
  await git(repo, ["init", "-b", "main"]);
  await git(repo, ["config", "user.name", "DevGuard Test"]);
  await git(repo, ["config", "user.email", "devguard@example.com"]);
  await writeFile(path.join(repo, "README.md"), "# Test\n");
  await git(repo, ["add", "README.md"]);
  await git(repo, ["commit", "-m", "initial"]);
  return repo;
}

async function exists(filePath: string): Promise<boolean> {
  return access(filePath)
    .then(() => true)
    .catch(() => false);
}

describe("installHooks", () => {
  it("formats hook installation output in Japanese", () => {
    expect(
      formatHookInstallResult({
        installed: ["pre-commit"],
        skipped: [{ hookName: "pre-push", reason: "already-exists" }],
      }),
    ).toContain("インストール済み:");
    expect(
      formatHookInstallResult({
        installed: [],
        skipped: [],
      }),
    ).toContain("変更されたhookはありません。");
  });

  it("installs executable pre-commit and pre-push hooks", async () => {
    const repo = await createRepo();

    const result = await installHooks(repo);

    const preCommitPath = path.join(repo, ".git", "hooks", "pre-commit");
    const prePushPath = path.join(repo, ".git", "hooks", "pre-push");
    expect(result.installed).toEqual(["pre-commit", "pre-push"]);
    expect(await exists(preCommitPath)).toBe(true);
    expect(await exists(prePushPath)).toBe(true);
    expect((await stat(preCommitPath)).mode & 0o111).toBeGreaterThan(0);
    expect((await stat(prePushPath)).mode & 0o111).toBeGreaterThan(0);
    expect(await readFile(preCommitPath, "utf8")).toContain("check --staged");
    expect(await readFile(prePushPath, "utf8")).toContain("push-check --agent-block");
  });

  it("does not overwrite existing hooks", async () => {
    const repo = await createRepo();
    const preCommitPath = path.join(repo, ".git", "hooks", "pre-commit");
    await writeFile(preCommitPath, "#!/bin/sh\necho existing\n");
    await chmod(preCommitPath, 0o755);

    const result = await installHooks(repo);

    expect(result.installed).toEqual(["pre-push"]);
    expect(result.skipped).toEqual([{ hookName: "pre-commit", reason: "already-exists" }]);
    expect(await readFile(preCommitPath, "utf8")).toBe("#!/bin/sh\necho existing\n");
  });

  it("allows low-risk commits through the installed pre-commit hook", async () => {
    const repo = await createRepo();
    await installHooks(repo);
    await writeFile(path.join(repo, "README.md"), "# Test\nupdated\n");
    await git(repo, ["add", "README.md"]);

    const { stdout } = await git(repo, ["commit", "-m", "docs update"], {
      DEVGUARD_BIN: `${tsxBin} ${cliPath}`,
    });

    expect(stdout).toContain("docs update");
  });

  it("blocks high-risk commits through the installed pre-commit hook", async () => {
    const repo = await createRepo();
    await installHooks(repo);
    await writeFile(path.join(repo, "debug.ts"), "console.log(user);\n");
    await git(repo, ["add", "debug.ts"]);

    await expect(
      git(repo, ["commit", "-m", "debug log"], {
        DEVGUARD_BIN: `${tsxBin} ${cliPath}`,
      }),
    ).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining("リスク: 高"),
    });
  });
});
