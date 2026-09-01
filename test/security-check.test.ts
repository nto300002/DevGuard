import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeNextModuleAst, analyzeNextModuleGraph, applySecurityAllowlist, applySecurityBaseline, detectNextModuleContext, loadSecurityBaseline, scanRepository, scanRepositoryDetailed, scanText, scanTextDetailed } from "../src/security-check.js";

describe("security flow scan", () => {
  it("detects Next.js client and route-handler execution contexts from module directives and paths", () => {
    expect(detectNextModuleContext("app/dashboard/page.tsx", '"use client";\nexport default function Page() {}')).toEqual({
      executionContext: "client",
      isRouteHandler: false,
      directives: ["use client"],
    });
    expect(detectNextModuleContext("app/api/users/route.ts", '"use server";\nexport async function GET() {}')).toEqual({
      executionContext: "route-handler",
      isRouteHandler: true,
      directives: ["use server"],
    });
  });

  it("attaches the Next.js execution context to TypeScript findings", () => {
    const findings = scanText("app/dashboard/page.tsx", '"use client";\nconst key = process.env.API_KEY;\nlogger.error(key);\n', "typescript");

    expect(findings).toEqual([
      expect.objectContaining({ executionContext: "client", lineNumber: 3 }),
    ]);
  });

  it("detects browser-only APIs and dangerouslySetInnerHTML from a Next.js AST", () => {
    const result = analyzeNextModuleAst(
      "app/dashboard/page.tsx",
      '"use server";\nwindow;\nlocalStorage.setItem("x", "value");\nreturn <div dangerouslySetInnerHTML={{ __html: html }} />;\n',
    );

    expect(result.executionContext).toBe("server");
    expect(result.browserOnlyUsages).toEqual([
      { name: "window", lineNumber: 2 },
      { name: "localStorage", lineNumber: 3 },
    ]);
    expect(result.dangerouslySetInnerHTML).toEqual([{ lineNumber: 4 }]);
  });

  it("does not detect Next.js AST patterns inside strings or comments", () => {
    const result = analyzeNextModuleAst(
      "app/page.tsx",
      'const text = "window localStorage dangerouslySetInnerHTML";\n// document sessionStorage\nexport default function Page() { return <div />; }\n',
    );

    expect(result.browserOnlyUsages).toEqual([]);
    expect(result.dangerouslySetInnerHTML).toEqual([]);
  });

  it("follows relative imports and records referenced Next.js module contexts", () => {
    const result = analyzeNextModuleGraph("app/page.tsx", {
      "app/page.tsx": '"use client";\nimport Widget from "./components/Widget";\nimport { value } from "../shared/value";\n',
      "app/components/Widget.tsx": "export default function Widget() { return <button />; }\n",
      "shared/value.ts": '"use server";\nexport const value = 1;\n',
    });

    expect(result.modules).toEqual([
      { filePath: "app/page.tsx", executionContext: "client" },
      { filePath: "app/components/Widget.tsx", executionContext: "unknown" },
      { filePath: "shared/value.ts", executionContext: "server" },
    ]);
    expect(result.unresolvedImports).toEqual([]);
  });

  it("does not loop on circular imports and reports unresolved relative imports", () => {
    const result = analyzeNextModuleGraph("app/page.tsx", {
      "app/page.tsx": 'import "./a";\nimport "./missing";\n',
      "app/a.ts": 'import "./page";\n',
    });

    expect(result.modules.map((module) => module.filePath)).toEqual(["app/page.tsx", "app/a.ts"]);
    expect(result.unresolvedImports).toEqual([{ from: "app/page.tsx", specifier: "./missing" }]);
  });

  it("detects TypeScript environment values flowing into logs", () => {
    const findings = scanText("lib/auth.ts", "const key = process.env.API_KEY;\nlogger.error(key);\n", "typescript");

    expect(findings).toEqual([
      expect.objectContaining({
        ruleId: "secret-to-log",
        source: "environment",
        sink: "logger",
        severity: "high",
        confidence: "high",
        filePath: "lib/auth.ts",
        lineNumber: 2,
      }),
    ]);
  });

  it("detects Python request data flowing into logs", () => {
    const findings = scanText("app/main.py", "payload = request.json()\nlogger.warning(\"request=%s\", payload)\n", "python");

    expect(findings).toEqual([
      expect.objectContaining({
        ruleId: "request-to-log",
        source: "request",
        sink: "logger",
        severity: "high",
        confidence: "high",
        lineNumber: 2,
      }),
    ]);
  });

  it("uses syntax-aware data flow instead of marking an unrelated log", () => {
    const findings = scanText(
      "src/auth.ts",
      "const token = process.env.RESET_TOKEN;\nlogger.error(\"request failed\");\nlogger.error(token);\n",
      "typescript",
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ lineNumber: 3, confidence: "high" });
  });

  it("detects PHP query values flowing into error logs", () => {
    const findings = scanText("app/Auth.php", "$token = $_GET['token'];\nerror_log($token);\n", "php");

    expect(findings).toEqual([
      expect.objectContaining({
        ruleId: "request-to-log",
        source: "request",
        sink: "logger",
        severity: "high",
        lineNumber: 2,
      }),
    ]);
  });

  it("detects Dart token values embedded in URLs and Flutter logs", () => {
    const findings = scanText("lib/auth.dart", 'final url = Uri.parse("https://example.test/reset?token=$token");\ndebugPrint(url.toString());\n', "dart");

    expect(findings.map((finding) => finding.ruleId)).toEqual(["secret-in-url", "sensitive-to-log"]);
    expect(findings.every((finding) => finding.severity === "high")).toBe(true);
  });

  it("reports malformed Dart delimiters as analysis issues", () => {
    const result = scanTextDetailed("lib/broken.dart", "void main() {\n  debugPrint(token);\n", "dart");

    expect(result.analysisIssues).toEqual([
      expect.objectContaining({ language: "dart", filePath: "lib/broken.dart", kind: "parse-error" }),
    ]);
  });

  it("does not treat delimiters in Dart strings or comments as syntax errors", () => {
    const result = scanTextDetailed("lib/valid.dart", "// }\nfinal value = '{';\nvoid main() {}\n", "dart");

    expect(result.analysisIssues).toHaveLength(0);
  });

  it("never includes the sensitive value in the finding", () => {
    const findings = scanText("src/token.ts", 'const token = "real-secret-value";\nconsole.log(token);\n', "typescript");

    expect(JSON.stringify(findings)).not.toContain("real-secret-value");
  });

  it("scans a repository while excluding dependency and build directories", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "devguard-security-"));
    await mkdir(path.join(root, "src"), { recursive: true });
    await mkdir(path.join(root, "node_modules", "ignored"), { recursive: true });
    await writeFile(path.join(root, "src", "auth.ts"), "const key = process.env.API_KEY;\nlogger.error(key);\n");
    await writeFile(path.join(root, "node_modules", "ignored", "bad.ts"), "console.log(process.env.API_KEY);\n");

    const findings = await scanRepository(root);

    expect(findings).toHaveLength(1);
    expect(findings[0].filePath).toBe("src/auth.ts");
  });

  it("excludes language-specific virtual environments, dependencies, and generated directories", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "devguard-security-generated-"));
    await mkdir(path.join(root, "src"), { recursive: true });
    for (const directory of [".venv", "venv", "env", "node_modules", "vendor", ".dart_tool", "build"]) {
      await mkdir(path.join(root, directory), { recursive: true });
      await writeFile(path.join(root, directory, "ignored.ts"), "const key = process.env.API_KEY;\nlogger.error(key);\n");
    }
    await writeFile(path.join(root, "src", "auth.ts"), "const key = process.env.API_KEY;\nlogger.error(key);\n");

    const findings = await scanRepository(root);

    expect(findings).toHaveLength(1);
    expect(findings[0].filePath).toBe("src/auth.ts");
  });

  it("detects GitHub Actions secrets flowing into deployment environment values", () => {
    const findings = scanText(
      ".github/workflows/deploy.yml",
      "steps:\n  - run: gcloud builds submit --substitutions=_DB_URL=${{ secrets.DB_URL }}\n  - run: gcloud run deploy api --update-env-vars DB_URL=${_DB_URL}\n",
      "yaml",
    );

    expect(findings).toEqual([
      expect.objectContaining({
        ruleId: "secret-to-deployment",
        sink: "deployment",
        severity: "high",
        confidence: "high",
      }),
    ]);
  });

  it("does not flag a Cloud Run Secret Manager reference as a plain secret flow", () => {
    const findings = scanText(
      "cloudbuild.yaml",
      "steps:\n  - name: gcr.io/cloud-builders/gcloud\n    args: [run, deploy, api, --update-secrets, DB_URL=database-url:latest]\n",
      "yaml",
    );

    expect(findings).toHaveLength(0);
  });

  it("detects Docker build args and environment values named as secrets", () => {
    const findings = scanText("Dockerfile", "ARG STRIPE_SECRET_KEY\nENV STRIPE_SECRET_KEY=$STRIPE_SECRET_KEY\n", "dockerfile");

    expect(findings).toEqual([
      expect.objectContaining({
        ruleId: "secret-to-deployment",
        sink: "deployment",
        severity: "high",
        confidence: "high",
      }),
    ]);
  });

  it("suppresses a matching finding only with valid non-expired metadata", () => {
    const finding = scanText("lib/auth.ts", "const key = process.env.API_KEY;\nlogger.error(key);\n", "typescript")[0];
    const [suppressed] = applySecurityAllowlist([finding], [
      { ruleId: "secret-to-log", filePath: "lib/auth.ts", reason: "temporary legacy integration", owner: "security-team", expires: "2099-12-31", issue: "#24" },
    ], new Date("2026-08-26T00:00:00Z"));

    expect(suppressed).toMatchObject({ suppressed: true, suppressionReason: "temporary legacy integration" });
  });

  it("does not suppress an expired allowlist entry", () => {
    const finding = scanText("lib/auth.ts", "const key = process.env.API_KEY;\nlogger.error(key);\n", "typescript")[0];
    const [result] = applySecurityAllowlist([finding], [
      { ruleId: "secret-to-log", filePath: "lib/auth.ts", reason: "expired exception", owner: "security-team", expires: "2026-08-25", issue: "#24" },
    ], new Date("2026-08-26T00:00:00Z"));

    expect(result).toMatchObject({ suppressed: false, suppressionExpired: true, severity: "high" });
  });

  it("reports TypeScript syntax errors as analysis issues", () => {
    const result = scanTextDetailed("src/broken.ts", "const = ;\n", "typescript");

    expect(result.findings).toHaveLength(0);
    expect(result.analysisIssues).toEqual([
      expect.objectContaining({ language: "typescript", filePath: "src/broken.ts", kind: "parse-error" }),
    ]);
  });

  it("reports malformed YAML instead of silently treating it as safe", () => {
    const result = scanTextDetailed(".github/workflows/ci.yml", "steps:\n  - run: [broken\n", "yaml");

    expect(result.analysisIssues).toEqual([
      expect.objectContaining({ language: "yaml", filePath: ".github/workflows/ci.yml", kind: "parse-error" }),
    ]);
  });

  it("reports Python syntax errors as analysis issues", () => {
    const result = scanTextDetailed("app/broken.py", "def broken(:\n    pass\n", "python");

    expect(result.findings).toHaveLength(0);
    expect(result.analysisIssues).toEqual([
      expect.objectContaining({ language: "python", filePath: "app/broken.py", kind: "parse-error" }),
    ]);
  });

  it("reports PHP parser errors as analysis issues", () => {
    const result = scanTextDetailed("app/broken.php", "<?php\nfunction broken( {\n", "php");

    expect(result.findings).toHaveLength(0);
    expect(result.analysisIssues).toEqual([
      expect.objectContaining({ language: "php", filePath: "app/broken.php", kind: "parse-error" }),
    ]);
  });

  it("supports explicit glob path exclusions without changing the default full scan", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "devguard-security-exclude-"));
    await mkdir(path.join(root, "src"), { recursive: true });
    await mkdir(path.join(root, "tests"), { recursive: true });
    await writeFile(path.join(root, "src", "auth.ts"), "const key = process.env.API_KEY;\nlogger.error(key);\n");
    await writeFile(path.join(root, "tests", "fixture.ts"), "const key = process.env.API_KEY;\nlogger.error(key);\n");

    const result = await scanRepositoryDetailed(root, { excludePaths: ["tests/**"] });

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].filePath).toBe("src/auth.ts");
  });

  it("supports wildcard rule IDs in the allowlist", () => {
    const finding = scanText("lib/auth.ts", "const key = process.env.API_KEY;\nlogger.error(key);\n", "typescript")[0];
    const [result] = applySecurityAllowlist([finding], [
      { ruleId: "secret-*", filePath: "lib/**", reason: "reviewed legacy boundary", owner: "security-team", expires: "2099-12-31", issue: "#24" },
    ]);

    expect(result.suppressed).toBe(true);
  });

  it("suppresses findings recorded in a baseline", () => {
    const finding = scanText("lib/auth.ts", "const key = process.env.API_KEY;\nlogger.error(key);\n", "typescript")[0];
    const [result] = applySecurityBaseline([finding], new Set([finding.id]));

    expect(result).toMatchObject({ suppressed: true, baseline: true, suppressionReason: "baseline" });
  });

  it("loads a baseline file and treats a missing baseline as empty", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "devguard-security-baseline-"));
    await writeFile(path.join(root, "baseline.json"), JSON.stringify({ findingIds: ["secret-to-log:lib/auth.ts:2"] }));

    await expect(loadSecurityBaseline(root, "baseline.json")).resolves.toEqual(new Set(["secret-to-log:lib/auth.ts:2"]));
    await expect(loadSecurityBaseline(root, "missing.json")).resolves.toEqual(new Set());
  });

  it("detects general SQL injection candidates and classifies them separately", () => {
    const result = scanTextDetailed(
      "src/users.ts",
      "const id = req.query.id;\ndb.query(`SELECT * FROM users WHERE id = ${id}`);\n",
      "typescript",
    );

    expect(result.findings).toEqual([
      expect.objectContaining({
        category: "general-vulnerability",
        ruleId: "general-sqli",
        cwe: "CWE-89",
        owaspCategory: "A03:2021-Injection",
        confidence: "medium",
        sink: "sql",
        lineNumber: 2,
      }),
    ]);
  });

  it("detects representative general vulnerability candidates in Python, PHP, and Dart", () => {
    const python = scanText("app/run.py", "subprocess.run(\"ping \" + request.args[\"host\"], shell=True)\n", "python");
    const php = scanText("public/name.php", "echo $_GET['name'];\n", "php");
    const dart = scanText("lib/api.dart", "final target = requestUrl;\nawait http.get(Uri.parse(target));\n", "dart");

    expect(python).toEqual([expect.objectContaining({ ruleId: "general-command-injection", category: "general-vulnerability", cwe: "CWE-78" })]);
    expect(php).toEqual([expect.objectContaining({ ruleId: "general-xss", category: "general-vulnerability", cwe: "CWE-79" })]);
    expect(dart).toEqual([expect.objectContaining({ ruleId: "general-ssrf", category: "general-vulnerability", cwe: "CWE-918" })]);
  });

  it("detects unsafe deserialization and path traversal candidates", () => {
    const python = scanText("app/load.py", "value = pickle.loads(request.data)\n", "python");
    const php = scanText("app/file.php", "include $_GET['page'];\n", "php");

    expect(python).toEqual([expect.objectContaining({ ruleId: "general-unsafe-deserialization", category: "general-vulnerability", sink: "deserialization" })]);
    expect(php).toEqual([expect.objectContaining({ ruleId: "general-path-traversal", category: "general-vulnerability", sink: "file" })]);
  });

  it("does not report parameterized SQL or fixed commands as general vulnerabilities", () => {
    const result = [
      ...scanText("src/users.ts", "db.query(\"SELECT * FROM users WHERE id = ?\", [id]);\n", "typescript"),
      ...scanText("app/run.py", "subprocess.run([\"/usr/bin/id\"], shell=False)\n", "python"),
    ];

    expect(result.filter((finding) => finding.category === "general-vulnerability")).toHaveLength(0);
  });
});
