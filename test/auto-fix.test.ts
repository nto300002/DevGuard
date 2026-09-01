import { describe, expect, it } from "vitest";
import { generateFixSuggestions } from "../src/auto-fix.js";

describe("auto-fix suggestions", () => {
  it("generates suggestions without changing source files", () => {
    const source = "logger.error(token);\n";
    const result = generateFixSuggestions([{
      id: "secret-1", ruleId: "secret-to-log", language: "typescript", severity: "high", confidence: "high",
      filePath: "src/auth.ts", lineNumber: 1, source: "secret", sink: "logger", flow: "secret -> logger",
      message: "Secretがログへ流入します。", remediation: "固定メッセージへ置き換えてください。", category: "security-flow",
    }], new Map([["src/auth.ts", source]]));

    expect(result).toEqual([expect.objectContaining({
      ruleId: "secret-to-log",
      filePath: "src/auth.ts",
      original: source,
      proposed: "logger.error('[REDACTED]');\n",
      applied: false,
    })]);
    expect(source).toBe("logger.error(token);\n");
  });

  it("does not propose automatic changes for SQL findings", () => {
    const result = generateFixSuggestions([{
      id: "sql-1", ruleId: "general-sqli", language: "typescript", severity: "high", confidence: "high",
      filePath: "src/db.ts", lineNumber: 1, source: "user-input", sink: "sql", flow: "input -> sql",
      message: "SQL Injection", remediation: "parameterized queryを使用してください。", category: "general-vulnerability",
    }], new Map([["src/db.ts", "db.query(`SELECT * FROM users WHERE id=${id}`);\n"]]));

    expect(result[0]).toMatchObject({ automatic: false, requiresApproval: true });
  });
});
