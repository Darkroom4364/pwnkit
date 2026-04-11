/**
 * Integration test scaffold for the full pwnkit scan pipeline.
 *
 * Exercises scan() end-to-end against the built-in test-target servers
 * (vulnerable + safe) with all API keys cleared so no real LLM calls are
 * made. The tests verify that the pipeline stages run to completion and
 * return structurally valid reports.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { Server } from "http";
import { scan } from "../scanner.js";

/* ------------------------------------------------------------------ */
/*  Environment: strip API keys so the baseline (non-AI) path is used */
/* ------------------------------------------------------------------ */
const savedEnv: Record<string, string | undefined> = {};
const API_KEY_VARS = [
  "OPENROUTER_API_KEY",
  "ANTHROPIC_API_KEY",
  "AZURE_OPENAI_API_KEY",
  "OPENAI_API_KEY",
];

/* ------------------------------------------------------------------ */
/*  Test-target servers                                               */
/* ------------------------------------------------------------------ */
let vulnServer: Server;
let safeServer: Server;
let vulnEndpoint = "";
let safeEndpoint = "";
let vulnMcpEndpoint = "";

beforeAll(async () => {
  // Save and clear API keys
  for (const key of API_KEY_VARS) {
    savedEnv[key] = process.env[key];
    process.env[key] = "";
  }

  // Dynamically import test-target servers (they live outside the core
  // package but are part of the monorepo workspace).
  const { startVulnerableServer } = await import(
    "../../../../test-targets/src/vulnerable-server.js"
  );
  const { startSafeServer } = await import(
    "../../../../test-targets/src/safe-server.js"
  );

  const vuln = startVulnerableServer(0);
  const safe = startSafeServer(0);

  vulnServer = vuln.server;
  safeServer = safe.server;
  vulnEndpoint = `http://localhost:${vuln.port}/v1/chat/completions`;
  safeEndpoint = `http://localhost:${safe.port}/v1/chat/completions`;
  vulnMcpEndpoint = `mcp://localhost:${vuln.port}/mcp`;
});

afterAll(async () => {
  // Shut down servers
  await Promise.all([
    new Promise<void>((resolve) => vulnServer?.close(() => resolve())),
    new Promise<void>((resolve) => safeServer?.close(() => resolve())),
  ]);

  // Restore API keys
  for (const key of API_KEY_VARS) {
    if (savedEnv[key] !== undefined) {
      process.env[key] = savedEnv[key];
    } else {
      delete process.env[key];
    }
  }
});

/* ------------------------------------------------------------------ */
/*  Full pipeline tests                                               */
/* ------------------------------------------------------------------ */
describe("scan pipeline integration", () => {
  it("completes a quick scan against the vulnerable target without throwing", async () => {
    const report = await scan({
      target: vulnEndpoint,
      depth: "quick",
      format: "json",
      timeout: 5_000,
    });

    expect(report).toBeDefined();
    expect(report.summary).toBeDefined();
    expect(report.findings).toBeDefined();
    expect(Array.isArray(report.findings)).toBe(true);
    expect(report.target).toBe(vulnEndpoint);
    expect(report.scanDepth).toBe("quick");
    expect(report.durationMs).toBeGreaterThan(0);
    expect(report.startedAt).toBeTruthy();
    expect(report.completedAt).toBeTruthy();
  }, 30_000);

  it("returns a clean report for the safe target", async () => {
    const report = await scan({
      target: safeEndpoint,
      depth: "quick",
      format: "json",
      timeout: 5_000,
    });

    expect(report.summary.totalFindings).toBe(0);
    expect(report.findings).toHaveLength(0);
  }, 30_000);

  it("runs default depth without errors", async () => {
    const report = await scan({
      target: safeEndpoint,
      depth: "default",
      format: "json",
      timeout: 5_000,
    });

    expect(report.summary).toBeDefined();
    expect(report.summary.totalFindings).toBe(0);
  }, 30_000);

  it("detects MCP vulnerabilities on the vulnerable target", async () => {
    const report = await scan({
      target: vulnMcpEndpoint,
      depth: "quick",
      format: "json",
      mode: "mcp",
      timeout: 5_000,
    });

    expect(report.summary.totalFindings).toBeGreaterThan(0);
    expect(
      report.findings.some((f) => f.title.toLowerCase().includes("mcp")),
    ).toBe(true);
  }, 30_000);

  it("emits stage events throughout the pipeline", async () => {
    const events: Array<{ type: string; stage?: string }> = [];

    await scan(
      {
        target: vulnEndpoint,
        depth: "quick",
        format: "json",
        timeout: 5_000,
      },
      (event) => {
        events.push({ type: event.type, stage: event.stage });
      },
    );

    // The pipeline must emit start/end for discovery, attack, verify, report
    const stageStarts = events
      .filter((e) => e.type === "stage:start")
      .map((e) => e.stage);
    expect(stageStarts).toContain("discovery");
    expect(stageStarts).toContain("attack");
    expect(stageStarts).toContain("verify");
    expect(stageStarts).toContain("report");

    const stageEnds = events
      .filter((e) => e.type === "stage:end")
      .map((e) => e.stage);
    expect(stageEnds).toContain("discovery");
    expect(stageEnds).toContain("attack");
    expect(stageEnds).toContain("verify");
    expect(stageEnds).toContain("report");
  }, 30_000);

  it("respects the timeout config without hanging", async () => {
    const start = Date.now();
    const report = await scan({
      target: safeEndpoint,
      depth: "quick",
      format: "json",
      timeout: 3_000,
    });
    const elapsed = Date.now() - start;

    expect(report).toBeDefined();
    // Should complete well within a generous upper bound
    expect(elapsed).toBeLessThan(30_000);
  }, 30_000);

  it("includes warnings array in report even when empty", async () => {
    const report = await scan({
      target: safeEndpoint,
      depth: "quick",
      format: "json",
      timeout: 5_000,
    });

    expect(report.warnings).toBeDefined();
    expect(Array.isArray(report.warnings)).toBe(true);
  }, 30_000);
});
