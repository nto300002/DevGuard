import packageJson from "../package.json" with { type: "json" };
import { describe, expect, it } from "vitest";

describe("package metadata", () => {
  it("exposes the safecheck CLI command from the unscoped package", () => {
    expect(packageJson.name).toBe("agent-safecheck");
    expect(packageJson.bin).toEqual({
      safecheck: "dist/cli.js",
    });
  });

  it("provides test and build scripts", () => {
    expect(packageJson.scripts.test).toBe("vitest run");
    expect(packageJson.scripts.build).toBe("tsc -p tsconfig.json");
  });
});
