import packageJson from "../package.json" with { type: "json" };
import { describe, expect, it } from "vitest";

describe("package metadata", () => {
  it("exposes the devguard CLI command", () => {
    expect(packageJson.bin).toEqual({
      devguard: "./dist/cli.js",
    });
  });

  it("provides test and build scripts", () => {
    expect(packageJson.scripts.test).toBe("vitest run");
    expect(packageJson.scripts.build).toBe("tsc -p tsconfig.json");
  });
});
