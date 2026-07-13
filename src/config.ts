import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { isMap, parse } from "yaml";

export const DEFAULT_PRESETS = ["typescript", "nextjs", "python", "fastapi", "php"] as const;

export type PresetId = (typeof DEFAULT_PRESETS)[number];

export type DevGuardConfig = {
  project: {
    name: string;
    defaultBranch: string;
  };
  presets: {
    enabled: PresetId[];
  };
  logPolicy: {
    preset: "personalStrictLog";
    aggregate: boolean;
    maxExamplesPerGroup: number;
  };
  pushCheck: {
    enabled: boolean;
    agentBlock: boolean;
    blockOn: {
      envSecretsAdded: boolean;
      outOfScopeDbConfig: boolean;
      personalStrictVariableLog: boolean;
    };
  };
  envConsistency: {
    enabled: boolean;
    requireEnvExampleUpdate: boolean;
  };
  issueScope: {
    enabled: boolean;
    defaultMode: "warn" | "error";
    allowedScopes: Record<string, { paths: string[] }>;
  };
  testCommands: Record<string, { command: string }>;
};

export type LoadedConfig = {
  config: DevGuardConfig;
  configPath: string;
  loaded: boolean;
  usingDefaultConfig: boolean;
};

export type PresetDefinition = {
  id: PresetId;
  filePatterns: string[];
  logPatterns: string[];
  envPatterns: string[];
  riskPatterns: string[];
  configPatterns: string[];
};

export type KeywordRule = {
  id: string;
  label: string;
  severity: "low" | "medium" | "high";
  targets: Array<"addedLines" | "removedLines" | "filePath" | "commitMessage" | "branchName">;
  patterns: string[];
  matchMode?: "contains" | "regex";
  caseSensitive?: boolean;
  excludePaths?: string[];
};

type RawConfig = Record<string, unknown>;

export class ConfigError extends Error {
  readonly exitCode = 1;

  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export const DEFAULT_CONFIG: DevGuardConfig = {
  project: {
    name: "sample-app",
    defaultBranch: "main",
  },
  presets: {
    enabled: [...DEFAULT_PRESETS],
  },
  logPolicy: {
    preset: "personalStrictLog",
    aggregate: true,
    maxExamplesPerGroup: 3,
  },
  pushCheck: {
    enabled: true,
    agentBlock: true,
    blockOn: {
      envSecretsAdded: true,
      outOfScopeDbConfig: true,
      personalStrictVariableLog: true,
    },
  },
  envConsistency: {
    enabled: true,
    requireEnvExampleUpdate: true,
  },
  issueScope: {
    enabled: true,
    defaultMode: "warn",
    allowedScopes: {
      frontend: {
        paths: ["src/app/**", "app/**", "src/pages/**", "pages/**", "src/components/**", "components/**"],
      },
      backend: {
        paths: ["app/**", "src/**", "routers/**", "routes/**", "services/**", "api/**"],
      },
      db: {
        paths: ["prisma/**", "migrations/**", "alembic/**", "database/**", "db/**", "models/**"],
      },
      config: {
        paths: [
          "package.json",
          "pnpm-lock.yaml",
          "package-lock.json",
          "tsconfig.json",
          "next.config.*",
          "requirements.txt",
          "pyproject.toml",
          "poetry.lock",
          "composer.json",
          "composer.lock",
          ".github/workflows/**",
          ".env.example",
        ],
      },
    },
  },
  testCommands: {
    typecheck: { command: "npm run typecheck" },
    lint: { command: "npm run lint" },
    test: { command: "npm test" },
    "python-test": { command: "pytest" },
    "python-lint": { command: "ruff check ." },
    "php-test": { command: "composer test" },
  },
};

const PRESET_DEFINITIONS: Record<PresetId, PresetDefinition> = {
  typescript: {
    id: "typescript",
    filePatterns: ["src/**/*.ts", "src/**/*.tsx", "**/*.ts", "**/*.tsx"],
    logPatterns: ["console.log(", "console.debug(", "debugger", "logger.debug("],
    envPatterns: ["process.env."],
    riskPatterns: ["as any", "@ts-ignore", "@ts-expect-error", "eslint-disable", "eval(", "innerHTML =", "dangerouslySetInnerHTML"],
    configPatterns: ["package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "tsconfig.json", "eslint.config.js"],
  },
  nextjs: {
    id: "nextjs",
    filePatterns: ["src/app/**", "app/**", "src/pages/**", "pages/**", "src/components/**", "components/**", "middleware.ts"],
    logPatterns: ["console.log(", "console.debug(", "debugger"],
    envPatterns: ["process.env.", "NEXT_PUBLIC_", ".env.local", ".env.production", ".env.development"],
    riskPatterns: [
      "NEXT_PUBLIC_SECRET",
      "NEXT_PUBLIC_TOKEN",
      "NEXT_PUBLIC_API_KEY",
      "NEXT_PUBLIC_PASSWORD",
      "NEXT_PUBLIC_PRIVATE_KEY",
      "NEXT_PUBLIC_CLIENT_SECRET",
    ],
    configPatterns: ["next.config.js", "next.config.mjs", "next.config.ts"],
  },
  python: {
    id: "python",
    filePatterns: ["**/*.py"],
    logPatterns: ["print(", "logging.debug(", "pprint(", "breakpoint("],
    envPatterns: ["os.environ", "os.getenv", "getenv(", "load_dotenv"],
    riskPatterns: ["eval(", "exec(", "compile(", "os.system(", "subprocess.call(", "subprocess.run(", "subprocess.Popen(", "pickle.loads(", "yaml.load("],
    configPatterns: ["requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile", "Pipfile.lock", ".env", ".env.example"],
  },
  fastapi: {
    id: "fastapi",
    filePatterns: ["app/**", "src/**", "main.py", "routers/**", "routes/**", "schemas/**", "models/**", "services/**", "dependencies/**"],
    logPatterns: ["print(", "logging.debug("],
    envPatterns: ["BaseSettings", "SettingsConfigDict", "pydantic_settings", "os.getenv", "os.environ"],
    riskPatterns: ["OAuth2PasswordBearer", "CORSMiddleware", "allow_origins", "allow_credentials", "Authorization", "Bearer"],
    configPatterns: ["alembic", "alembic.ini", "migrations/", "models/", "schemas/", "database/", "db/"],
  },
  php: {
    id: "php",
    filePatterns: ["**/*.php", "config/"],
    logPatterns: ["var_dump(", "print_r(", "dump(", "dd("],
    envPatterns: ["getenv(", "$_ENV", "$_SERVER"],
    riskPatterns: ["eval(", "exec(", "shell_exec(", "system(", "passthru(", "popen(", "unserialize(", "include(", "require("],
    configPatterns: ["composer.json", "composer.lock", ".env", ".env.example", "config/"],
  },
};

const DEFAULT_KEYWORD_RULES: KeywordRule[] = [
  {
    id: "secrets-credentials",
    label: "Secrets and credentials",
    severity: "high",
    targets: ["addedLines", "filePath"],
    patterns: [
      "API_KEY",
      "SECRET",
      "CLIENT_SECRET",
      "TOKEN",
      "ACCESS_TOKEN",
      "REFRESH_TOKEN",
      "PASSWORD",
      "PRIVATE_KEY",
      "SECRET_KEY",
      "DATABASE_URL",
      "DB_PASSWORD",
      "JWT_SECRET",
      "SESSION_SECRET",
      "COOKIE_SECRET",
      "OAUTH_CLIENT_SECRET",
      "STRIPE_SECRET_KEY",
      "OPENAI_API_KEY",
      "ANTHROPIC_API_KEY",
      "AWS_ACCESS_KEY_ID",
      "AWS_SECRET_ACCESS_KEY",
      "SUPABASE_SERVICE_ROLE_KEY",
    ],
  },
  {
    id: "work-in-progress",
    label: "Work-in-progress markers",
    severity: "medium",
    targets: ["addedLines", "commitMessage", "branchName"],
    patterns: ["TODO", "FIXME", "WIP", "TEMP", "HACK", "あとで", "後で", "仮", "暫定", "一旦", "とりあえず", "未対応", "未実装", "確認中"],
  },
  {
    id: "ai-output-traces",
    label: "AI output or copy-paste traces",
    severity: "medium",
    targets: ["addedLines"],
    patterns: ["as an AI", "I apologize", "Certainly", "Here is", "placeholder", "sample implementation", "dummy", "replace this", "your code here", "TODO: implement"],
  },
  {
    id: "bypass-markers",
    label: "Check bypass markers",
    severity: "medium",
    targets: ["addedLines"],
    patterns: ["@ts-ignore", "@ts-expect-error", "eslint-disable", "type: ignore", "# noqa", "pylint: disable", "phpcs:ignore", "as any"],
  },
  {
    id: "dangerous-apis",
    label: "Dangerous APIs",
    severity: "high",
    targets: ["addedLines"],
    patterns: ["eval(", "Function(", "new Function", "innerHTML", "dangerouslySetInnerHTML", "document.write", "exec(", "system(", "shell_exec(", "subprocess.run", "os.system", "Runtime.getRuntime().exec"],
  },
  {
    id: "browser-storage-risk",
    label: "Browser storage usage",
    severity: "medium",
    targets: ["addedLines"],
    patterns: ["localStorage", "sessionStorage"],
  },
  {
    id: "destructive-db",
    label: "Destructive DB changes",
    severity: "high",
    targets: ["addedLines"],
    patterns: ["DROP TABLE", "DROP DATABASE", "TRUNCATE", "DELETE FROM", "ALTER TABLE", "CASCADE", "DROP COLUMN", "DROP INDEX", "rollback", "down migration"],
  },
];

export async function loadConfig(gitRoot: string): Promise<LoadedConfig> {
  const configPath = path.join(gitRoot, ".devguard.yml");

  if (!(await pathExists(configPath))) {
    return {
      config: cloneConfig(DEFAULT_CONFIG),
      configPath,
      loaded: false,
      usingDefaultConfig: true,
    };
  }

  let parsed: unknown;
  try {
    parsed = parse(await readFile(configPath, "utf8"));
  } catch (error) {
    throw new ConfigError(`Invalid .devguard.yml: ${error instanceof Error ? error.message : String(error)}`);
  }

  return {
    config: validateConfig(parsed),
    configPath,
    loaded: true,
    usingDefaultConfig: false,
  };
}

export function validateConfig(raw: unknown): DevGuardConfig {
  if (raw == null) {
    return cloneConfig(DEFAULT_CONFIG);
  }

  if (!isPlainObject(raw)) {
    throw new ConfigError(".devguard.yml must be a mapping object");
  }

  const merged = mergeConfig(cloneConfig(DEFAULT_CONFIG), raw);
  validatePresets(merged.presets.enabled);
  validateLogPolicy(merged.logPolicy.preset);
  validateIssueScope(merged.issueScope.defaultMode);
  return merged;
}

export function loadEnabledPresets(enabled: readonly string[]): PresetDefinition[] {
  validatePresets(enabled);
  return enabled.map((id) => PRESET_DEFINITIONS[id as PresetId]);
}

export function mergeDefaultKeywordDatabase(extraRules: KeywordRule[] = []): KeywordRule[] {
  return [...DEFAULT_KEYWORD_RULES.map((rule) => ({ ...rule, targets: [...rule.targets], patterns: [...rule.patterns] })), ...extraRules];
}

function pathExists(targetPath: string): Promise<boolean> {
  return access(targetPath)
    .then(() => true)
    .catch(() => false);
}

function cloneConfig(config: DevGuardConfig): DevGuardConfig {
  return structuredClone(config) as DevGuardConfig;
}

function mergeConfig(base: DevGuardConfig, raw: RawConfig): DevGuardConfig {
  if (isPlainObject(raw.project)) {
    base.project = {
      ...base.project,
      ...pickStringFields(raw.project, ["name", "defaultBranch"]),
    };
  }

  if (isPlainObject(raw.presets) && Array.isArray(raw.presets.enabled)) {
    base.presets.enabled = raw.presets.enabled.map((preset) => {
      if (typeof preset !== "string") {
        throw new ConfigError("presets.enabled must contain only strings");
      }
      return preset as PresetId;
    });
  }

  if (isPlainObject(raw.logPolicy)) {
    const preset = raw.logPolicy.preset;
    if (preset !== undefined && preset !== "personalStrictLog") {
      throw new ConfigError(`Unsupported logPolicy.preset: ${String(preset)}`);
    }

    base.logPolicy = {
      ...base.logPolicy,
      ...pickBooleanFields(raw.logPolicy, ["aggregate"]),
      ...pickNumberFields(raw.logPolicy, ["maxExamplesPerGroup"]),
      ...(preset === "personalStrictLog" ? { preset } : {}),
    };
  }

  if (isPlainObject(raw.pushCheck)) {
    base.pushCheck = {
      ...base.pushCheck,
      ...pickBooleanFields(raw.pushCheck, ["enabled", "agentBlock"]),
      blockOn: isPlainObject(raw.pushCheck.blockOn)
        ? {
            ...base.pushCheck.blockOn,
            ...pickBooleanFields(raw.pushCheck.blockOn, ["envSecretsAdded", "outOfScopeDbConfig", "personalStrictVariableLog"]),
          }
        : base.pushCheck.blockOn,
    };
  }

  if (isPlainObject(raw.envConsistency)) {
    base.envConsistency = {
      ...base.envConsistency,
      ...pickBooleanFields(raw.envConsistency, ["enabled", "requireEnvExampleUpdate"]),
    };
  }

  if (isPlainObject(raw.issueScope)) {
    const defaultMode = raw.issueScope.defaultMode;
    if (defaultMode !== undefined && defaultMode !== "warn" && defaultMode !== "error") {
      throw new ConfigError(`Unsupported issueScope.defaultMode: ${String(defaultMode)}`);
    }

    base.issueScope = {
      ...base.issueScope,
      ...pickBooleanFields(raw.issueScope, ["enabled"]),
      ...(defaultMode === "warn" || defaultMode === "error" ? { defaultMode } : {}),
      allowedScopes: parseAllowedScopes(raw.issueScope.allowedScopes, base.issueScope.allowedScopes),
    };
  }

  if (isPlainObject(raw.testCommands)) {
    base.testCommands = parseTestCommands(raw.testCommands, base.testCommands);
  }

  return base;
}

function validatePresets(enabled: readonly string[]): void {
  if (enabled.length === 0) {
    throw new ConfigError("presets.enabled must include at least one preset");
  }

  for (const preset of enabled) {
    if (!isPresetId(preset)) {
      throw new ConfigError(`Unknown preset: ${preset}`);
    }
  }
}

function validateLogPolicy(preset: string): void {
  if (preset !== "personalStrictLog") {
    throw new ConfigError(`Unsupported logPolicy.preset: ${preset}`);
  }
}

function validateIssueScope(defaultMode: string): void {
  if (defaultMode !== "warn" && defaultMode !== "error") {
    throw new ConfigError(`Unsupported issueScope.defaultMode: ${defaultMode}`);
  }
}

function isPresetId(value: string): value is PresetId {
  return DEFAULT_PRESETS.includes(value as PresetId);
}

function parseAllowedScopes(raw: unknown, fallback: Record<string, { paths: string[] }>): Record<string, { paths: string[] }> {
  if (raw === undefined) {
    return fallback;
  }

  if (!isPlainObject(raw)) {
    throw new ConfigError("issueScope.allowedScopes must be a mapping object");
  }

  const scopes: Record<string, { paths: string[] }> = {};
  for (const [scopeName, scopeValue] of Object.entries(raw)) {
    if (!isPlainObject(scopeValue) || !Array.isArray(scopeValue.paths)) {
      throw new ConfigError(`issueScope.allowedScopes.${scopeName}.paths must be an array`);
    }

    scopes[scopeName] = {
      paths: scopeValue.paths.map((item) => {
        if (typeof item !== "string") {
          throw new ConfigError(`issueScope.allowedScopes.${scopeName}.paths must contain only strings`);
        }
        return item;
      }),
    };
  }

  return scopes;
}

function parseTestCommands(raw: RawConfig, fallback: Record<string, { command: string }>): Record<string, { command: string }> {
  const testCommands = { ...fallback };
  for (const [key, value] of Object.entries(raw)) {
    if (!isPlainObject(value) || typeof value.command !== "string") {
      throw new ConfigError(`testCommands.${key}.command must be a string`);
    }
    testCommands[key] = { command: value.command };
  }
  return testCommands;
}

function pickStringFields<T extends string>(raw: RawConfig, keys: readonly T[]): Partial<Record<T, string>> {
  const result: Partial<Record<T, string>> = {};
  for (const key of keys) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "string") {
        throw new ConfigError(`${key} must be a string`);
      }
      result[key] = raw[key];
    }
  }
  return result;
}

function pickBooleanFields<T extends string>(raw: RawConfig, keys: readonly T[]): Partial<Record<T, boolean>> {
  const result: Partial<Record<T, boolean>> = {};
  for (const key of keys) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "boolean") {
        throw new ConfigError(`${key} must be a boolean`);
      }
      result[key] = raw[key];
    }
  }
  return result;
}

function pickNumberFields<T extends string>(raw: RawConfig, keys: readonly T[]): Partial<Record<T, number>> {
  const result: Partial<Record<T, number>> = {};
  for (const key of keys) {
    if (raw[key] !== undefined) {
      if (typeof raw[key] !== "number") {
        throw new ConfigError(`${key} must be a number`);
      }
      result[key] = raw[key];
    }
  }
  return result;
}

function isPlainObject(value: unknown): value is RawConfig {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !isMap(value);
}
