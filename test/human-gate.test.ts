import { describe, expect, it } from "vitest";
import { evaluateHumanGate, formatHumanGateComment } from "../src/human-gate.js";

describe("human gate", () => {
  it("requires human approval for new high-risk secret findings", () => {
    const result = evaluateHumanGate([{
      id: "secret-1", ruleId: "secret-github-token", language: "typescript", severity: "high", confidence: "high",
      filePath: "src/config.ts", lineNumber: 4, source: "secret", sink: "file", flow: "secret -> file",
      message: "Secretを検出しました。", remediation: "revoke / rotate / removeしてください。", category: "general-vulnerability",
    }]);

    expect(result.required).toBe(true);
    expect(result.items[0]).toMatchObject({ filePath: "src/config.ts", reason: expect.stringContaining("Secret") });
  });

  it("does not gate a low-risk finding and generates review todos for gated findings", () => {
    const result = evaluateHumanGate([{
      id: "low-1", ruleId: "general-xss", language: "typescript", severity: "low", confidence: "low",
      filePath: "src/view.ts", lineNumber: 8, source: "user-input", sink: "html", flow: "input -> html",
      message: "候補です。", remediation: "確認してください。", category: "general-vulnerability",
    }]);

    expect(result.required).toBe(false);
    expect(formatHumanGateComment(result)).toContain("Human Gate: 不要");
  });
});
