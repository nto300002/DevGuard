import { execFile } from "node:child_process";
import { access, realpath } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type RootDetectionResult = {
  cwd: string;
  gitRoot: string;
  relativeCwdFromRoot: string;
  configPath: string;
  configExists: boolean;
  isInsideWorkTree: boolean;
  isBareRepository: boolean;
};

export class RootDetectionError extends Error {
  readonly exitCode: 2;

  constructor(message: string) {
    super(message);
    this.name = "RootDetectionError";
    this.exitCode = 2;
  }
}

export async function runGit(cwd: string, args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync("git", args, {
      cwd,
      maxBuffer: 1024 * 1024 * 20,
    });
    return stdout.trimEnd();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new RootDetectionError(`Git command failed: git ${args.join(" ")}\n${message}`);
  }
}

export async function detectRoot(cwd = process.cwd()): Promise<RootDetectionResult> {
  const absoluteCwd = await realpath(cwd);
  const insideWorkTree = (await runGit(absoluteCwd, ["rev-parse", "--is-inside-work-tree"])).trim() === "true";
  const isBareRepository = (await runGit(absoluteCwd, ["rev-parse", "--is-bare-repository"])).trim() === "true";

  if (!insideWorkTree || isBareRepository) {
    throw new RootDetectionError("DevGuard must run inside a non-bare Git work tree.");
  }

  const gitRoot = await realpath(await runGit(absoluteCwd, ["rev-parse", "--show-toplevel"]));
  const configPath = path.join(gitRoot, ".devguard.yml");

  return {
    cwd: absoluteCwd,
    gitRoot,
    relativeCwdFromRoot: toRootRelativePath(gitRoot, absoluteCwd) || ".",
    configPath,
    configExists: await exists(configPath),
    isInsideWorkTree: insideWorkTree,
    isBareRepository,
  };
}

export function resolveConfigPath(gitRoot: string): string {
  return path.join(gitRoot, ".devguard.yml");
}

export function normalizePath(filePath: string): string {
  return filePath.replace(/\\/g, "/");
}

export function toRootRelativePath(gitRoot: string, targetPath: string): string {
  const absoluteRoot = path.resolve(gitRoot);
  const absoluteTarget = path.resolve(targetPath);
  const relativePath = path.relative(absoluteRoot, absoluteTarget);

  if (relativePath === "") {
    return "";
  }

  if (relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
    throw new RootDetectionError(`Path is outside Git root: ${targetPath}`);
  }

  return normalizePath(relativePath);
}

export function formatDoctorResult(result: RootDetectionResult): string {
  return [
    "DevGuard doctor",
    "",
    "Git:",
    `- inside work tree: ${result.isInsideWorkTree}`,
    `- bare repository: ${result.isBareRepository}`,
    `- git root: ${result.gitRoot}`,
    `- current directory: ${result.cwd}`,
    `- relative cwd: ${result.relativeCwdFromRoot}`,
    "",
    "Config:",
    `- config path: ${result.configPath}`,
    `- config loaded: ${result.configExists}`,
    `- using default config: ${!result.configExists}`,
    "",
    "Path:",
    "- root-relative paths enabled: true",
    "- separator normalized to /: true",
    "",
  ].join("\n");
}

async function exists(filePath: string): Promise<boolean> {
  return access(filePath)
    .then(() => true)
    .catch(() => false);
}
