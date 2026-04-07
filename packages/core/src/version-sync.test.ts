import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { VERSION } from "@pwnkit/shared";

const here = dirname(fileURLToPath(import.meta.url));
// packages/core/src/ -> packages/core -> packages -> repo root
const rootPackageJson = resolve(here, "..", "..", "..", "package.json");

describe("VERSION constant <-> root package.json", () => {
  // Regression test for the v0.7.1 ship where the root package.json was
  // bumped to 0.7.1 but @pwnkit/shared's VERSION constant was left at
  // 0.7.0, so the published CLI reported the old version on `--version`.
  // This test fails the build if the two ever drift again.
  it("matches the root package.json version field", () => {
    const pkg = JSON.parse(readFileSync(rootPackageJson, "utf8"));
    expect(pkg.version).toBe(VERSION);
  });
});
