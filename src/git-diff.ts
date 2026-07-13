import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type ChangedFileStatus = "added" | "modified" | "deleted" | "renamed" | "copied" | "type-changed" | "unmerged" | "unknown";

export type ChangedFile = {
  status: ChangedFileStatus;
  path: string;
  previousPath?: string;
};

export type DiffLine = {
  type: "added" | "removed";
  filePath: string;
  lineNumber: number;
  content: string;
};

export type GitDiffResult = {
  files: ChangedFile[];
  lines: DiffLine[];
  rawNameStatus: string;
  rawPatch: string;
};

type HunkState = {
  oldLine: number;
  newLine: number;
};

export async function getStagedFiles(gitRoot: string): Promise<ChangedFile[]> {
  const nameStatus = await runGit(gitRoot, ["diff", "--cached", "--find-renames", "--name-status"]);
  return parseNameStatus(nameStatus);
}

export async function getStagedDiff(gitRoot: string): Promise<GitDiffResult> {
  const [rawNameStatus, rawPatch] = await Promise.all([
    runGit(gitRoot, ["diff", "--cached", "--find-renames", "--name-status"]),
    runGit(gitRoot, ["diff", "--cached", "--find-renames", "--unified=0"]),
  ]);

  return {
    files: parseNameStatus(rawNameStatus),
    lines: parseDiffLines(rawPatch),
    rawNameStatus,
    rawPatch,
  };
}

export async function getWorktreeDiff(gitRoot: string): Promise<GitDiffResult> {
  const [rawNameStatus, rawPatch, untracked] = await Promise.all([
    runGit(gitRoot, ["diff", "--find-renames", "--name-status"]),
    runGit(gitRoot, ["diff", "--find-renames", "--unified=0"]),
    getUntrackedDiff(gitRoot),
  ]);

  const trackedFiles = parseNameStatus(rawNameStatus);
  const trackedLines = parseDiffLines(rawPatch);

  return {
    files: dedupeChangedFiles([...trackedFiles, ...untracked.files]),
    lines: [...trackedLines, ...untracked.lines],
    rawNameStatus: [rawNameStatus, untracked.rawNameStatus].filter(Boolean).join("\n"),
    rawPatch: [rawPatch, untracked.rawPatch].filter(Boolean).join("\n"),
  };
}

export async function getAllDiff(gitRoot: string): Promise<GitDiffResult> {
  const [rawNameStatus, rawPatch, untracked] = await Promise.all([
    runGit(gitRoot, ["diff", "HEAD", "--find-renames", "--name-status"]),
    runGit(gitRoot, ["diff", "HEAD", "--find-renames", "--unified=0"]),
    getUntrackedDiff(gitRoot),
  ]);

  const trackedFiles = parseNameStatus(rawNameStatus);
  const trackedLines = parseDiffLines(rawPatch);

  return {
    files: dedupeChangedFiles([...trackedFiles, ...untracked.files]),
    lines: [...trackedLines, ...untracked.lines],
    rawNameStatus: [rawNameStatus, untracked.rawNameStatus].filter(Boolean).join("\n"),
    rawPatch: [rawPatch, untracked.rawPatch].filter(Boolean).join("\n"),
  };
}

export async function getDefaultBranchDiff(gitRoot: string, defaultBranch: string): Promise<GitDiffResult> {
  const diffBase = `${defaultBranch}...HEAD`;
  const [rawNameStatus, rawPatch] = await Promise.all([
    runGit(gitRoot, ["diff", diffBase, "--find-renames", "--name-status"]),
    runGit(gitRoot, ["diff", diffBase, "--find-renames", "--unified=0"]),
  ]);

  return {
    files: parseNameStatus(rawNameStatus),
    lines: parseDiffLines(rawPatch),
    rawNameStatus,
    rawPatch,
  };
}

export function parseNameStatus(output: string): ChangedFile[] {
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [rawStatus = "", firstPath = "", secondPath] = line.split("\t");
      const statusCode = rawStatus[0] ?? "";
      const status = mapNameStatus(statusCode);

      if ((status === "renamed" || status === "copied") && secondPath !== undefined) {
        return {
          status,
          path: normalizeGitPath(secondPath),
          previousPath: normalizeGitPath(firstPath),
        };
      }

      return {
        status,
        path: normalizeGitPath(firstPath),
      };
    });
}

export function parseDiffLines(patch: string): DiffLine[] {
  const result: DiffLine[] = [];
  let oldPath: string | null = null;
  let newPath: string | null = null;
  let activePath: string | null = null;
  let hunk: HunkState | null = null;

  for (const line of patch.split(/\r?\n/)) {
    if (line.startsWith("diff --git ")) {
      oldPath = null;
      newPath = null;
      activePath = null;
      hunk = null;
      continue;
    }

    if (line.startsWith("--- ")) {
      oldPath = parsePatchPath(line.slice(4));
      continue;
    }

    if (line.startsWith("+++ ")) {
      newPath = parsePatchPath(line.slice(4));
      activePath = newPath ?? oldPath;
      continue;
    }

    if (line.startsWith("@@ ")) {
      hunk = parseHunkHeader(line);
      continue;
    }

    if (!hunk || !activePath) {
      continue;
    }

    if (line.startsWith("+") && !line.startsWith("+++")) {
      result.push({
        type: "added",
        filePath: activePath,
        lineNumber: hunk.newLine,
        content: line.slice(1),
      });
      hunk.newLine += 1;
      continue;
    }

    if (line.startsWith("-") && !line.startsWith("---")) {
      result.push({
        type: "removed",
        filePath: oldPath ?? activePath,
        lineNumber: hunk.oldLine,
        content: line.slice(1),
      });
      hunk.oldLine += 1;
      continue;
    }

    if (line.startsWith(" ")) {
      hunk.oldLine += 1;
      hunk.newLine += 1;
    }
  }

  return result;
}

export function normalizeGitPath(filePath: string): string {
  return filePath.replace(/\\/g, "/").replace(/^\/+/, "");
}

async function runGit(cwd: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync("git", args, {
    cwd,
    maxBuffer: 1024 * 1024 * 20,
  });
  return stdout;
}

async function getUntrackedDiff(gitRoot: string): Promise<GitDiffResult> {
  const rawFiles = await runGit(gitRoot, ["ls-files", "--others", "--exclude-standard"]);
  const files = rawFiles
    .split(/\r?\n/)
    .map((line) => normalizeGitPath(line.trim()))
    .filter(Boolean);

  const lines: DiffLine[] = [];
  const rawPatchParts: string[] = [];
  for (const filePath of files) {
    const content = await readTextFileIfPossible(path.join(gitRoot, filePath));
    if (content === null) {
      continue;
    }

    rawPatchParts.push(`diff --git /dev/null b/${filePath}`);
    rawPatchParts.push("--- /dev/null");
    rawPatchParts.push(`+++ b/${filePath}`);

    const fileLines = content.split(/\r?\n/);
    const normalizedLines = fileLines.at(-1) === "" ? fileLines.slice(0, -1) : fileLines;
    rawPatchParts.push(`@@ -0,0 +1,${normalizedLines.length} @@`);

    normalizedLines.forEach((line, index) => {
      lines.push({
        type: "added",
        filePath,
        lineNumber: index + 1,
        content: line,
      });
      rawPatchParts.push(`+${line}`);
    });
  }

  return {
    files: files.map((filePath) => ({ status: "added", path: filePath })),
    lines,
    rawNameStatus: files.map((filePath) => `A\t${filePath}`).join("\n"),
    rawPatch: rawPatchParts.join("\n"),
  };
}

async function readTextFileIfPossible(filePath: string): Promise<string | null> {
  try {
    const buffer = await readFile(filePath);
    if (buffer.includes(0)) {
      return null;
    }
    return buffer.toString("utf8");
  } catch {
    return null;
  }
}

function dedupeChangedFiles(files: ChangedFile[]): ChangedFile[] {
  const seen = new Set<string>();
  return files.filter((file) => {
    const key = `${file.status}:${file.path}:${file.previousPath ?? ""}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function mapNameStatus(statusCode: string): ChangedFileStatus {
  switch (statusCode) {
    case "A":
      return "added";
    case "M":
      return "modified";
    case "D":
      return "deleted";
    case "R":
      return "renamed";
    case "C":
      return "copied";
    case "T":
      return "type-changed";
    case "U":
      return "unmerged";
    default:
      return "unknown";
  }
}

function parsePatchPath(rawPath: string): string | null {
  const trimmed = rawPath.trim();
  if (trimmed === "/dev/null") {
    return null;
  }

  return normalizeGitPath(trimmed.replace(/^[ab]\//, ""));
}

function parseHunkHeader(header: string): HunkState {
  const match = /^@@ -(?<oldStart>\d+)(?:,\d+)? \+(?<newStart>\d+)(?:,\d+)? @@/.exec(header);
  if (!match?.groups) {
    return { oldLine: 0, newLine: 0 };
  }

  return {
    oldLine: Number.parseInt(match.groups.oldStart, 10),
    newLine: Number.parseInt(match.groups.newStart, 10),
  };
}
