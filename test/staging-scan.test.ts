import { describe, expect, it } from "vitest";
import { parseRuntimeFindings, validateStagingUrl } from "../src/staging-scan.js";

describe("staging runtime scan", () => {
  it("accepts staging URLs and rejects production URLs", () => {
    expect(validateStagingUrl("https://staging.example.test")).toEqual({ valid: true });
    expect(validateStagingUrl("https://api.example.com")).toMatchObject({ valid: false });
  });

  it("converts runtime results into findings without retaining the target URL", () => {
    const findings = parseRuntimeFindings({
      results: [{ ruleId: "dast-xss", severity: "high", confidence: "high", path: "/search", message: "Reflected input" }],
    }, "https://staging.example.test");

    expect(findings).toEqual([
      expect.objectContaining({
        ruleId: "dast-xss",
        filePath: "/search",
        detectionOrigin: "runtime",
        severity: "high",
        confidence: "high",
      }),
    ]);
    expect(JSON.stringify(findings)).not.toContain("staging.example.test");
  });
});
