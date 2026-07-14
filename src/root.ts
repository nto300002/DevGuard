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
    throw new RootDetectionError(`Gitコマンドに失敗しました: git ${args.join(" ")}\n${message}`);
  }
}

export async function detectRoot(cwd = process.cwd()): Promise<RootDetectionResult> {
  const absoluteCwd = await realpath(cwd);
  const insideWorkTree = (await runGit(absoluteCwd, ["rev-parse", "--is-inside-work-tree"])).trim() === "true";
  const isBareRepository = (await runGit(absoluteCwd, ["rev-parse", "--is-bare-repository"])).trim() === "true";

  if (!insideWorkTree || isBareRepository) {
    throw new RootDetectionError("DevGuardはbareではないGit作業ツリー内で実行してください。");
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
    throw new RootDetectionError(`パスがGit rootの外にあります: ${targetPath}`);
  }

  return normalizePath(relativePath);
}

export function formatDoctorResult(result: RootDetectionResult): string {
  return [
    "DevGuard doctor",
    "",
    "Git:",
    `- 作業ツリー内: ${result.isInsideWorkTree}`,
    `- bare repositoryではない: ${!result.isBareRepository}`,
    `- Git root: ${result.gitRoot}`,
    `- 現在のディレクトリ: ${result.cwd}`,
    `- rootからの相対パス: ${result.relativeCwdFromRoot}`,
    "",
    "設定:",
    `- 設定ファイル: ${result.configPath}`,
    `- 設定読み込み済み: ${result.configExists}`,
    `- デフォルト設定を使用: ${!result.configExists}`,
    "",
    "パス:",
    "- root相対パス: 有効",
    "- 区切り文字を / に正規化: true",
    "",
  ].join("\n");
}

async function exists(filePath: string): Promise<boolean> {
  return access(filePath)
    .then(() => true)
    .catch(() => false);
}
