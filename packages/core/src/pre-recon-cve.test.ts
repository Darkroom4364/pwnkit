/**
 * Tests for pre-recon-cve.ts
 *
 * Validates the white-box pre-recon CVE check: manifest discovery,
 * empty-report rendering, and the system-prompt formatter. The actual
 * `npm audit` / `pip-audit` runs are not exercised (they require the
 * tools to be installed and a real package-lock.json with vulns) — those
 * are integration-level concerns. The unit tests focus on the parts of
 * the module that are pure functions over reports.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  runPreReconCveCheck,
  formatPreReconForPrompt,
  type CveAdvisory,
  type PreReconCveReport,
} from "./pre-recon-cve.js";

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "pre-recon-test-"));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

// ────────────────────────────────────────────────────────────────────
// runPreReconCveCheck — manifest discovery + empty-tree behavior
// ────────────────────────────────────────────────────────────────────

describe("runPreReconCveCheck", () => {
  it("returns an empty report for a non-existent path", () => {
    const report = runPreReconCveCheck(join(tmp, "does-not-exist"));
    expect(report.advisories).toHaveLength(0);
    expect(report.manifestsScanned).toHaveLength(0);
    expect(report.manifestsSkipped).toHaveLength(0);
  });

  it("returns an empty report for a tree with no manifests", () => {
    mkdirSync(join(tmp, "src"), { recursive: true });
    writeFileSync(join(tmp, "src", "main.go"), "package main");
    writeFileSync(join(tmp, "README.md"), "# hi");
    const report = runPreReconCveCheck(tmp);
    expect(report.advisories).toHaveLength(0);
  });

  it("skips node_modules / .git / build artifact dirs", () => {
    // Create a manifest INSIDE node_modules — should be ignored
    mkdirSync(join(tmp, "node_modules", "lodash"), { recursive: true });
    writeFileSync(
      join(tmp, "node_modules", "lodash", "package-lock.json"),
      "{}",
    );
    mkdirSync(join(tmp, ".git"), { recursive: true });
    writeFileSync(join(tmp, ".git", "package-lock.json"), "{}");
    mkdirSync(join(tmp, "dist"), { recursive: true });
    writeFileSync(join(tmp, "dist", "package-lock.json"), "{}");

    const report = runPreReconCveCheck(tmp);
    // None of those should have been scanned
    expect(report.manifestsScanned).toHaveLength(0);
    expect(report.advisories).toHaveLength(0);
  });

  it("does not throw when an audit tool errors out", () => {
    // A package-lock.json with garbage content. `npm audit` will
    // either fail to parse or run on a real install — either way
    // the runner should swallow the error and not throw.
    writeFileSync(join(tmp, "package-lock.json"), "{ not valid json");
    expect(() => runPreReconCveCheck(tmp)).not.toThrow();
  });

  it("records duration in milliseconds", () => {
    const report = runPreReconCveCheck(tmp);
    expect(typeof report.durationMs).toBe("number");
    expect(report.durationMs).toBeGreaterThanOrEqual(0);
  });
});

// ────────────────────────────────────────────────────────────────────
// formatPreReconForPrompt
// ────────────────────────────────────────────────────────────────────

function fakeReport(advisories: CveAdvisory[]): PreReconCveReport {
  return {
    advisories,
    manifestsScanned: ["package-lock.json"],
    manifestsSkipped: [],
    durationMs: 100,
  };
}

describe("formatPreReconForPrompt", () => {
  it("returns null on an empty report", () => {
    expect(formatPreReconForPrompt(fakeReport([]))).toBeNull();
  });

  it("renders a single advisory as a markdown bullet", () => {
    const out = formatPreReconForPrompt(
      fakeReport([
        {
          manifest: "package-lock.json",
          tool: "npm-audit",
          package: "lodash",
          version: "4.17.20",
          id: "CVE-2021-23337",
          title: "Command injection in lodash template",
          severity: "high",
        },
      ]),
    );
    expect(out).not.toBeNull();
    expect(out).toContain("Priority CVE leads from source-tree audit");
    expect(out).toContain("`lodash`@4.17.20");
    expect(out).toContain("**high**");
    expect(out).toContain("Command injection in lodash template");
    expect(out).toContain("CVE-2021-23337");
  });

  it("dedupes by package + advisory ID", () => {
    const out = formatPreReconForPrompt(
      fakeReport([
        {
          manifest: "package-lock.json",
          tool: "npm-audit",
          package: "lodash",
          id: "CVE-2021-23337",
          title: "first",
          severity: "high",
        },
        {
          manifest: "package-lock.json",
          tool: "npm-audit",
          package: "lodash",
          id: "CVE-2021-23337",
          title: "duplicate",
          severity: "high",
        },
      ]),
    );
    // Only one occurrence of lodash@CVE-2021-23337 in output
    expect(out).not.toBeNull();
    const matches = (out!.match(/CVE-2021-23337/g) ?? []).length;
    expect(matches).toBe(1);
  });

  it("caps to 30 advisories with a 'more suppressed' note", () => {
    const many: CveAdvisory[] = Array.from({ length: 50 }, (_, i) => ({
      manifest: "package-lock.json",
      tool: "npm-audit",
      package: `pkg-${i}`,
      id: `CVE-2026-${1000 + i}`,
      title: `vuln ${i}`,
      severity: "high" as const,
    }));
    const out = formatPreReconForPrompt(fakeReport(many));
    expect(out).not.toBeNull();
    // 30 rendered, 20 suppressed
    const bullets = (out!.match(/^- /gm) ?? []).length;
    expect(bullets).toBe(30);
    expect(out).toContain("20 more advisories suppressed");
  });

  it("includes severity, package, and CVE ID for every entry", () => {
    const out = formatPreReconForPrompt(
      fakeReport([
        {
          manifest: "package-lock.json",
          tool: "npm-audit",
          package: "express",
          id: "GHSA-aaaa-bbbb-cccc",
          title: "RCE in express",
          severity: "critical",
        },
        {
          manifest: "requirements.txt",
          tool: "pip-audit",
          package: "django",
          version: "3.2.0",
          id: "CVE-2024-12345",
          title: "SQL injection in QuerySet",
          severity: "high",
        },
      ]),
    );
    expect(out).toContain("`express`");
    expect(out).toContain("**critical**");
    expect(out).toContain("GHSA-aaaa-bbbb-cccc");
    expect(out).toContain("`django`@3.2.0");
    expect(out).toContain("**high**");
    expect(out).toContain("CVE-2024-12345");
  });

  it("includes URL when present", () => {
    const out = formatPreReconForPrompt(
      fakeReport([
        {
          manifest: "package-lock.json",
          tool: "npm-audit",
          package: "lodash",
          id: "CVE-X",
          title: "x",
          severity: "high",
          url: "https://github.com/advisories/GHSA-x",
        },
      ]),
    );
    expect(out).toContain("https://github.com/advisories/GHSA-x");
  });

  it("frames the prompt as 'investigate first priority'", () => {
    const out = formatPreReconForPrompt(
      fakeReport([
        {
          manifest: "package-lock.json",
          tool: "npm-audit",
          package: "lodash",
          id: "CVE-1",
          title: "x",
          severity: "high",
        },
      ]),
    );
    expect(out).toContain("first priority");
    expect(out).toContain("running target");
  });
});
