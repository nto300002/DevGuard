import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  ConfigError,
  DEFAULT_PRESETS,
  loadConfig,
  loadEnabledPresets,
  mergeDefaultKeywordDatabase,
  validateConfig,
} from "../src/config.js";

async function createTempRoot(): Promise<string> {
  return mkdtemp(path.join(os.tmpdir(), "devguard-config-"));
}

describe("loadConfig", () => {
  it("uses default config when .devguard.yml is missing", async () => {
    const gitRoot = await createTempRoot();

    const result = await loadConfig(gitRoot);

    expect(result.loaded).toBe(false);
    expect(result.usingDefaultConfig).toBe(true);
    expect(result.configPath).toBe(path.join(gitRoot, ".devguard.yml"));
    expect(result.config.project.defaultBranch).toBe("main");
    expect(result.config.presets.enabled).toEqual(DEFAULT_PRESETS);
  });

  it("loads a valid .devguard.yml and merges defaults", async () => {
    const gitRoot = await createTempRoot();
    await writeFile(
      path.join(gitRoot, ".devguard.yml"),
      [
        "project:",
        '  name: "custom-app"',
        '  defaultBranch: "develop"',
        "presets:",
        "  enabled:",
        '    - "typescript"',
        '    - "python"',
      ].join("\n"),
    );

    const result = await loadConfig(gitRoot);

    expect(result.loaded).toBe(true);
    expect(result.usingDefaultConfig).toBe(false);
    expect(result.config.project.name).toBe("custom-app");
    expect(result.config.project.defaultBranch).toBe("develop");
    expect(result.config.presets.enabled).toEqual(["typescript", "python"]);
    expect(result.config.logPolicy.preset).toBe("personalStrictLog");
    expect(result.config.pushCheck.blockOn.envSecretsAdded).toBe(true);
  });

  it("throws ConfigError with exit code 1 for invalid config", async () => {
    const gitRoot = await createTempRoot();
    await writeFile(path.join(gitRoot, ".devguard.yml"), "project: [");

    await expect(loadConfig(gitRoot)).rejects.toMatchObject({
      name: "ConfigError",
      exitCode: 1,
    });
  });
});

describe("validateConfig", () => {
  it("rejects unknown presets", () => {
    expect(() =>
      validateConfig({
        presets: {
          enabled: ["typescript", "ruby"],
        },
      }),
    ).toThrow(ConfigError);
  });

  it("accepts the MVP preset names", () => {
    const config = validateConfig({
      presets: {
        enabled: ["typescript", "nextjs", "python", "fastapi", "php"],
      },
    });

    expect(config.presets.enabled).toEqual(["typescript", "nextjs", "python", "fastapi", "php"]);
  });
});

describe("preset and keyword helpers", () => {
  it("loads enabled presets in config order", () => {
    const presets = loadEnabledPresets(["php", "typescript"]);

    expect(presets.map((preset) => preset.id)).toEqual(["php", "typescript"]);
    expect(presets[0]?.envPatterns).toContain("getenv(");
    expect(presets[1]?.logPatterns).toContain("console.log(");
  });

  it("merges the default keyword database", () => {
    const rules = mergeDefaultKeywordDatabase();

    expect(rules.some((rule) => rule.patterns.includes("API_KEY"))).toBe(true);
    expect(rules.some((rule) => rule.patterns.includes("TODO"))).toBe(true);
    expect(rules.some((rule) => rule.patterns.includes("DROP TABLE"))).toBe(true);
    expect(rules).toContainEqual(
      expect.objectContaining({
        id: "browser-storage-risk",
        severity: "medium",
        patterns: expect.arrayContaining(["localStorage", "sessionStorage"]),
      }),
    );
  });
});
