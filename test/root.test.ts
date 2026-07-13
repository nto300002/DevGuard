import { execFile } from "node:child_process";
import { mkdir, mkdtemp, realpath, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { detectRoot, normalizePath, RootDetectionError, toRootRelativePath } from "../src/root.js";

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = path.join(repoRoot, "src", "cli.ts");
const tsxBin = path.join(repoRoot, "node_modules", ".bin", "tsx");

async function git(cwd: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync("git", args, { cwd });
  return stdout;
}

async function createRepo(): Promise<string> {
  const repo = await mkdtemp(path.join(os.tmpdir(), "devguard-root-"));
  await git(repo, ["init", "-b", "main"]);
  await git(repo, ["config", "user.name", "DevGuard Test"]);
  await git(repo, ["config", "user.email", "devguard@example.com"]);
  await writeFile(path.join(repo, "README.md"), "# Test\n");
  await git(repo, ["add", "README.md"]);
  await git(repo, ["commit", "-m", "initial"]);
  return repo;
}

describe("path normalization", () => {
  it("normalizes Windows-style separators to slash separators", () => {
    expect(normalizePath("src\\components\\Button.tsx")).toBe("src/components/Button.tsx");
  });

  it("returns root-relative slash paths", () => {
    const root = path.join(os.tmpdir(), "devguard-root");
    const target = path.join(root, "src", "components", "Button.tsx");

    expect(toRootRelativePath(root, target)).toBe("src/components/Button.tsx");
  });

  it("rejects files outside the Git root", () => {
    expect(() => toRootRelativePath("/repo/app", "/repo/other/file.ts")).toThrow(RootDetectionError);
  });
});

describe("detectRoot", () => {
  it("detects the same git root from root and nested directories", async () => {
    const repo = await createRepo();
    const nested = path.join(repo, "src", "features", "one");
    await mkdir(nested, { recursive: true });

    const fromRoot = await detectRoot(repo);
    const fromNested = await detectRoot(nested);
    const realRepo = await realpath(repo);

    expect(fromRoot.gitRoot).toBe(realRepo);
    expect(fromNested.gitRoot).toBe(realRepo);
    expect(fromRoot.configPath).toBe(path.join(realRepo, ".devguard.yml"));
    expect(fromNested.configPath).toBe(path.join(realRepo, ".devguard.yml"));
    expect(fromNested.relativeCwdFromRoot).toBe("src/features/one");
  });

  it("detects .devguard.yml at the git root", async () => {
    const repo = await createRepo();
    await writeFile(path.join(repo, ".devguard.yml"), "project:\n  name: root-test\n");

    const result = await detectRoot(repo);
    const realRepo = await realpath(repo);

    expect(result.configPath).toBe(path.join(realRepo, ".devguard.yml"));
    expect(result.configExists).toBe(true);
  });

  it("throws a controlled error outside Git", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "devguard-non-git-"));

    await expect(detectRoot(directory)).rejects.toMatchObject({
      name: "RootDetectionError",
      exitCode: 2,
    });
  });
});

describe("devguard doctor", () => {
  it("prints git, config, and path diagnostics", async () => {
    const repo = await createRepo();
    const realRepo = await realpath(repo);

    const { stdout } = await execFileAsync(tsxBin, [cliPath, "doctor"], { cwd: repo });

    expect(stdout).toContain("DevGuard doctor");
    expect(stdout).toContain("inside work tree: true");
    expect(stdout).toContain(`git root: ${realRepo}`);
    expect(stdout).toContain("config loaded: false");
    expect(stdout).toContain("using default config: true");
    expect(stdout).toContain("separator normalized to /: true");
  });
});
