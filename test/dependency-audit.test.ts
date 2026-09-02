import { describe, expect, it } from "vitest";
import { parseComposerAuditJson, parseNpmAuditJson, parseOsvAuditJson, parsePipAuditJson, runComposerAudit, runNpmAudit, runPipAudit } from "../src/dependency-audit.js";

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

  it("converts pip-audit JSON into common findings", () => {
    const findings = parsePipAuditJson([
      {
        name: "jinja2",
        version: "3.1.2",
        vulns: [{ id: "CVE-2024-22195", fix_versions: ["3.1.3"], description: "sandbox escape" }],
      },
    ]);

    expect(findings).toEqual([
      expect.objectContaining({
        ruleId: "dependency-vulnerability",
        language: "python",
        filePath: "requirements.txt",
        dependencyName: "jinja2",
        advisoryId: "CVE-2024-22195",
        affectedRange: "==3.1.2",
        fixedVersion: "3.1.3",
        severity: "medium",
      }),
    ]);
  });

  it("runs pip-audit and parses JSON even when vulnerabilities are found", async () => {
    const result = await runPipAudit("/tmp/project", async () => ({
      stdout: JSON.stringify([{ name: "jinja2", version: "3.1.2", vulns: [{ id: "CVE-2024-22195", fix_versions: ["3.1.3"] }] }]),
      stderr: "",
      status: 1,
    }));

    expect(result.analysisIssue).toBeUndefined();
    expect(result.findings).toEqual([expect.objectContaining({ dependencyName: "jinja2", advisoryId: "CVE-2024-22195" })]);
  });

  it("reports an analysis issue when pip-audit is unavailable", async () => {
    const result = await runPipAudit("/tmp/project", async () => ({ stdout: "", stderr: "pip-audit: command not found", status: 127 }));

    expect(result.findings).toEqual([]);
    expect(result.analysisIssue).toEqual(expect.objectContaining({ kind: "parser-unavailable", filePath: "requirements.txt" }));
  });

  it("converts composer audit JSON into common findings", () => {
    const findings = parseComposerAuditJson({
      advisories: {
        "symfony/http-kernel": [{
          advisoryId: "CVE-2024-50340",
          affectedVersions: "<6.4.12",
          title: "Access control issue",
          cve: "CVE-2024-50340",
          reportedAt: "2024-11-12T00:00:00+00:00",
        }],
      },
    });

    expect(findings).toEqual([
      expect.objectContaining({
        ruleId: "dependency-vulnerability",
        language: "php",
        filePath: "composer.lock",
        dependencyName: "symfony/http-kernel",
        advisoryId: "CVE-2024-50340",
        affectedRange: "<6.4.12",
        severity: "medium",
      }),
    ]);
  });

  it("runs composer audit and parses JSON despite a vulnerability exit code", async () => {
    const result = await runComposerAudit("/tmp/project", async () => ({
      stdout: JSON.stringify({ advisories: { "symfony/http-kernel": [{ advisoryId: "CVE-2024-50340" }] } }),
      stderr: "",
      status: 1,
    }));

    expect(result.analysisIssue).toBeUndefined();
    expect(result.findings).toEqual([expect.objectContaining({ dependencyName: "symfony/http-kernel", advisoryId: "CVE-2024-50340" })]);
  });

  it("reports an analysis issue when composer is unavailable", async () => {
    const result = await runComposerAudit("/tmp/project", async () => ({ stdout: "", stderr: "composer: command not found", status: 127 }));

    expect(result.findings).toEqual([]);
    expect(result.analysisIssue).toEqual(expect.objectContaining({ kind: "parser-unavailable", filePath: "composer.lock" }));
  });

  it("converts Pub OSV audit results into common findings", () => {
    const findings = parseOsvAuditJson({
      results: [{
        package: { name: "http", version: "1.2.0", ecosystem: "Pub" },
        vulnerabilities: [{
          id: "GHSA-8v7x-j7fc-8m3m",
          summary: "Improper validation",
          affected: [{ ranges: [{ events: [{ introduced: "0" }, { fixed: "1.2.1" }] }] }],
        }],
      }],
    });

    expect(findings).toEqual([
      expect.objectContaining({
        ruleId: "dependency-vulnerability",
        language: "dart",
        filePath: "pubspec.lock",
        dependencyName: "http",
        advisoryId: "GHSA-8v7x-j7fc-8m3m",
        affectedRange: "<1.2.1",
        fixedVersion: "1.2.1",
      }),
    ]);
  });
});
