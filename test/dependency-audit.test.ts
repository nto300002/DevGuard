import { describe, expect, it } from "vitest";
import { parseNpmAuditJson, runNpmAudit } from "../src/dependency-audit.js";

describe("dependency audit", () => {
  it("converts npm audit vulnerabilities into common findings", () => {
    const findings = parseNpmAuditJson({
      vulnerabilities: {
        lodash: {
          severity: "high",
          range: "<4.17.21",
          via: [{ source: 1106913, title: "Command Injection", url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm" }],
          fixAvailable: { name: "lodash", version: "4.17.21", isSemVerMajor: false },
        },
      },
    });

    expect(findings).toEqual([
      expect.objectContaining({
        ruleId: "dependency-vulnerability",
        dependencyName: "lodash",
        severity: "high",
        advisoryId: "GHSA-35jh-r3h4-6jhm",
        affectedRange: "<4.17.21",
        fixedVersion: "4.17.21",
        category: "general-vulnerability",
      }),
    ]);
  });

  it("does not copy arbitrary audit fields or credentials into a finding", () => {
    const findings = parseNpmAuditJson({
      vulnerabilities: {
        "private-package": {
          severity: "moderate",
          range: "*",
          via: [{ source: "CVE-2025-1234", title: "Issue", url: "https://example.test/advisory", notes: "token=real-secret" }],
        },
      },
      metadata: { token: "real-secret" },
    });

    expect(JSON.stringify(findings)).not.toContain("real-secret");
    expect(findings[0]).toMatchObject({ advisoryId: "CVE-2025-1234", fixedVersion: undefined });
  });

  it("runs npm audit and parses JSON even when npm exits with vulnerabilities", async () => {
    const result = await runNpmAudit("/tmp/project", async () => ({
      stdout: JSON.stringify({ vulnerabilities: { lodash: { severity: "high", via: [{ source: "CVE-2025-1234" }] } } }),
      stderr: "",
      status: 1,
    }));

    expect(result.analysisIssue).toBeUndefined();
    expect(result.findings).toEqual([expect.objectContaining({ dependencyName: "lodash", advisoryId: "CVE-2025-1234" })]);
  });

  it("reports an analysis issue when npm audit cannot produce JSON", async () => {
    const result = await runNpmAudit("/tmp/project", async () => ({ stdout: "", stderr: "network unavailable", status: 1 }));

    expect(result.findings).toEqual([]);
    expect(result.analysisIssue).toEqual(expect.objectContaining({ kind: "parse-error", filePath: "package-lock.json" }));
  });
});
