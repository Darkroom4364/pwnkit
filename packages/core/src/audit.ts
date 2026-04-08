import { execFileSync, execSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import type {
  AuditConfig,
  AuditReport,
  NpmAuditFinding,
  SemgrepFinding,
  Finding,
  ScanConfig,
  Severity,
} from "@pwnkit/shared";
import type { ScanEvent, ScanListener } from "./scanner.js";
import { auditAgentPrompt } from "./analysis-prompts.js";
import { runAnalysisAgent } from "./agent-runner.js";
import { restoreHistoricalPackageFixture, shouldUseHistoricalPackageFallback } from "./historical-package-fallback.js";
import { bufferToString, runSemgrepScan } from "./shared-analysis.js";
import { scanForMaliciousPatterns } from "./malicious-detector.js";
import { postProcessPackageAuditFindings } from "./package-audit-suppressor.js";

export interface PackageAuditOptions {
  config: AuditConfig;
  onEvent?: ScanListener;
}

interface InstalledPackage {
  name: string;
  version: string;
  path: string;
  tempDir: string;
}

interface OsvVulnerability {
  id?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ type?: string; score?: string }>;
  database_specific?: { severity?: string };
  references?: Array<{ type?: string; url?: string }>;
  affected?: Array<{
    ranges?: Array<{
      type?: string;
      events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
  }>;
}

/**
 * Install an npm package in a temporary directory and return its path.
 */
function installPackage(
  packageName: string,
  requestedVersion: string | undefined,
  emit: ScanListener,
): InstalledPackage {
  const tempDir = join(tmpdir(), `pwnkit-audit-${randomUUID().slice(0, 8)}`);
  mkdirSync(tempDir, { recursive: true });

  const spec = requestedVersion
    ? `${packageName}@${requestedVersion}`
    : `${packageName}@latest`;

  emit({
    type: "stage:start",
    stage: "discovery",
    message: `Installing ${spec}...`,
  });

  try {
    // Initialize a minimal package.json so npm install works cleanly
    execFileSync("npm", ["init", "-y", "--silent"], {
      cwd: tempDir,
      timeout: 15_000,
      stdio: "pipe",
    });

    execFileSync("npm", ["install", spec, "--ignore-scripts", "--no-audit", "--no-fund"], {
      cwd: tempDir,
      timeout: 120_000,
      stdio: "pipe",
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (shouldUseHistoricalPackageFallback(msg)) {
      const restored = restoreHistoricalPackageFixture(packageName, tempDir, emit);
      if (restored) {
        return {
          ...restored,
          tempDir,
        };
      }
    }
    rmSync(tempDir, { recursive: true, force: true });
    throw new Error(`Failed to install ${spec}: ${msg}`);
  }

  // Resolve actual installed version from package.json
  const pkgJsonPath = join(tempDir, "node_modules", packageName, "package.json");
  if (!existsSync(pkgJsonPath)) {
    // Try scoped package path
    rmSync(tempDir, { recursive: true, force: true });
    throw new Error(
      `Package ${packageName} not found after install. Check the package name.`,
    );
  }

  const pkgJson = JSON.parse(readFileSync(pkgJsonPath, "utf-8"));
  const installedVersion = pkgJson.version as string;
  const packagePath = join(tempDir, "node_modules", packageName);

  emit({
    type: "stage:end",
    stage: "discovery",
    message: `Installed ${packageName}@${installedVersion}`,
  });

  return {
    name: packageName,
    version: installedVersion,
    path: packagePath,
    tempDir,
  };
}

function runNpmAudit(
  projectDir: string,
  emit: ScanListener,
): NpmAuditFinding[] {
  emit({
    type: "stage:start",
    stage: "discovery",
    message: "Running npm audit...",
  });

  let rawOutput = "";

  try {
    rawOutput = execSync("npm audit --json", {
      cwd: projectDir,
      timeout: 120_000,
      stdio: "pipe",
    }).toString("utf-8");
  } catch (err) {
    const stdout =
      err && typeof err === "object" && "stdout" in err
        ? (err.stdout as Buffer | string | undefined)
        : undefined;
    const stderr =
      err && typeof err === "object" && "stderr" in err
        ? (err.stderr as Buffer | string | undefined)
        : undefined;

    rawOutput = bufferToString(stdout) || bufferToString(stderr) || "";
  }

  const findings = parseNpmAuditOutput(rawOutput);

  emit({
    type: "stage:end",
    stage: "discovery",
    message: `npm audit: ${findings.length} advisories`,
  });

  return findings;
}

function parseNpmAuditOutput(rawOutput: string): NpmAuditFinding[] {
  if (!rawOutput.trim()) {
    return [];
  }

  try {
    const raw = JSON.parse(rawOutput) as {
      vulnerabilities?: Record<
        string,
        {
          name?: string;
          severity?: string;
          via?: Array<string | Record<string, unknown>>;
          range?: string;
          fixAvailable?: boolean | { name?: string; version?: string } | string;
        }
      >;
    };

    return Object.entries(raw.vulnerabilities ?? {}).map(([pkgName, vuln]) => {
      const via = (vuln.via ?? []).map((entry) => {
        if (typeof entry === "string") {
          return entry;
        }

        const source = typeof entry.source === "number" ? `GHSA:${entry.source}` : null;
        const title = typeof entry.title === "string" ? entry.title : null;
        const name = typeof entry.name === "string" ? entry.name : null;

        return [name, title, source].filter(Boolean).join(" - ") || "unknown advisory";
      });

      const firstObjectVia = (vuln.via ?? []).find(
        (entry): entry is Record<string, unknown> => typeof entry === "object" && entry !== null,
      );

      return {
        name: vuln.name ?? pkgName,
        severity: normalizeSeverity(vuln.severity),
        title:
          (typeof firstObjectVia?.title === "string" && firstObjectVia.title) ||
          via[0] ||
          "npm audit advisory",
        range: vuln.range,
        source:
          typeof firstObjectVia?.source === "number" || typeof firstObjectVia?.source === "string"
            ? (firstObjectVia.source as number | string)
            : undefined,
        url: typeof firstObjectVia?.url === "string" ? firstObjectVia.url : undefined,
        via,
        fixAvailable: formatFixAvailable(vuln.fixAvailable),
      };
    });
  } catch {
    return [];
  }
}

function normalizeSeverity(value: string | undefined): Severity {
  switch ((value ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "moderate":
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}

function formatFixAvailable(
  fixAvailable: boolean | { name?: string; version?: string } | string | undefined,
): boolean | string {
  if (typeof fixAvailable === "string" || typeof fixAvailable === "boolean") {
    return fixAvailable;
  }

  if (fixAvailable && typeof fixAvailable === "object") {
    const next = [fixAvailable.name, fixAvailable.version].filter(Boolean).join("@");
    return next || true;
  }

  return false;
}

function parseCvssSeverity(score: string | undefined): Severity | undefined {
  if (!score) return undefined;
  const match = score.match(/CVSS:\d\.\d\/[^/]*\/[^/]*\/[^/]*\/[^/]*\/[^/]*\/[^/]*\/[^/]*\/[^/]*\/([^/]+)/i);
  if (match) {
    const label = match[1]?.toUpperCase();
    if (label === "CRITICAL") return "critical";
    if (label === "HIGH") return "high";
    if (label === "MEDIUM") return "medium";
    if (label === "LOW") return "low";
  }
  return undefined;
}

function extractOsvSeverity(vuln: OsvVulnerability): Severity {
  const dbSeverity = vuln.database_specific?.severity;
  if (typeof dbSeverity === "string" && dbSeverity.length > 0) {
    return normalizeSeverity(dbSeverity);
  }
  for (const sev of vuln.severity ?? []) {
    const parsed = parseCvssSeverity(sev.score);
    if (parsed) return parsed;
  }
  return "medium";
}

function extractOsvRange(vuln: OsvVulnerability): string | undefined {
  const segments: string[] = [];
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      if (range.type !== "SEMVER") continue;
      const parts = (range.events ?? []).flatMap((event) => {
        const items: string[] = [];
        if (event.introduced) items.push(`introduced:${event.introduced}`);
        if (event.fixed) items.push(`fixed:${event.fixed}`);
        if (event.last_affected) items.push(`last_affected:${event.last_affected}`);
        return items;
      });
      if (parts.length > 0) {
        segments.push(parts.join(","));
      }
    }
  }
  return segments.length > 0 ? segments.join(" | ") : undefined;
}

function extractOsvFix(vuln: OsvVulnerability): boolean | string {
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return false;
}

export function parseOsvAdvisories(
  packageName: string,
  raw: unknown,
): NpmAuditFinding[] {
  const vulns = Array.isArray((raw as { vulns?: unknown[] })?.vulns)
    ? ((raw as { vulns?: unknown[] }).vulns as OsvVulnerability[])
    : [];

  return vulns.map((vuln) => {
    const aliases = [...new Set([vuln.id, ...(vuln.aliases ?? [])].filter(Boolean) as string[])];
    const source = aliases[0];
    const url = vuln.references?.find((ref) => typeof ref.url === "string")?.url;
    const title =
      (typeof vuln.summary === "string" && vuln.summary.trim()) ||
      (typeof vuln.details === "string" && vuln.details.trim().slice(0, 120)) ||
      source ||
      "OSV advisory";

    return {
      name: packageName,
      severity: extractOsvSeverity(vuln),
      title,
      range: extractOsvRange(vuln),
      source,
      url,
      via: aliases.length > 0 ? aliases : ["OSV"],
      fixAvailable: extractOsvFix(vuln),
    };
  });
}

export async function queryOsvAdvisories(
  packageName: string,
  version: string,
  emit?: ScanListener,
): Promise<NpmAuditFinding[]> {
  emit?.({
    type: "stage:start",
    stage: "discovery",
    message: `Querying OSV for ${packageName}@${version}...`,
  });

  try {
    const res = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: { ecosystem: "npm", name: packageName },
        version,
      }),
    });

    if (!res.ok) {
      emit?.({
        type: "stage:end",
        stage: "discovery",
        message: `OSV lookup failed: ${res.status}`,
      });
      return [];
    }

    const json = await res.json();
    const findings = parseOsvAdvisories(packageName, json);
    emit?.({
      type: "stage:end",
      stage: "discovery",
      message: `OSV: ${findings.length} advisories`,
    });
    return findings;
  } catch {
    emit?.({
      type: "stage:end",
      stage: "discovery",
      message: "OSV lookup unavailable",
    });
    return [];
  }
}

function mergeAdvisories(
  primary: NpmAuditFinding[],
  extra: NpmAuditFinding[],
): NpmAuditFinding[] {
  const seen = new Set(
    primary.map((finding) => `${finding.name}|${finding.title}|${finding.source ?? ""}`),
  );
  const merged = [...primary];
  for (const finding of extra) {
    const key = `${finding.name}|${finding.title}|${finding.source ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(finding);
  }
  return merged;
}

function severityRank(severity: Severity): number {
  switch (severity) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    case "info":
    default:
      return 1;
  }
}

export function summarizeKnownAdvisoriesFinding(
  pkg: InstalledPackage,
  advisories: NpmAuditFinding[],
): Finding | null {
  if (advisories.length === 0) return null;

  const ordered = [...advisories].sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity),
  );
  const topSeverity = ordered[0]?.severity ?? "medium";
  const lines = ordered.slice(0, 8).map((advisory) => {
    const id = advisory.source ? ` (${advisory.source})` : "";
    const fix =
      typeof advisory.fixAvailable === "string" && advisory.fixAvailable.length > 0
        ? ` — fix: ${advisory.fixAvailable}`
        : "";
    return `- [${advisory.severity.toUpperCase()}] ${advisory.title}${id}${fix}`;
  });

  return {
    id: randomUUID(),
    templateId: "known-package-advisories",
    title: `${pkg.name}@${pkg.version} matches ${advisories.length} known advisory${advisories.length === 1 ? "" : "ies"}`,
    description:
      `Deterministic package-version match against registry advisory data for the audited root package.\n\n` +
      `${lines.join("\n")}` +
      (advisories.length > lines.length
        ? `\n- ... ${advisories.length - lines.length} more advisory matches`
        : ""),
    severity: topSeverity,
    category: "known-vulnerable-package" as any,
    status: "open" as any,
    evidence: {
      request: `advisory lookup for ${pkg.name}@${pkg.version}`,
      response: ordered
        .slice(0, 8)
        .map((advisory) => `${advisory.title} | ${advisory.source ?? "unknown"} | ${advisory.url ?? "no-url"}`)
        .join("\n"),
      analysis:
        "Deterministic root-package advisory match (OSV/npm audit). This finding does not depend on the LLM reading the source code or rediscovering the issue manually.",
    },
    confidence: 0.95,
    timestamp: Date.now(),
  };
}

function buildCliAuditPrompt(
  pkg: InstalledPackage,
  semgrepFindings: SemgrepFinding[],
  npmAuditFindings: NpmAuditFinding[],
): string {
  const semgrepContext = semgrepFindings.length > 0
    ? semgrepFindings
        .slice(0, 30)
        .map((f, i) => `  ${i + 1}. [${f.severity}] ${f.ruleId} — ${f.path}:${f.startLine}: ${f.message}`)
        .join("\n")
    : "  None.";

  const npmContext = npmAuditFindings.length > 0
    ? npmAuditFindings
        .slice(0, 30)
        .map((f, i) => `  ${i + 1}. [${f.severity}] ${f.name}: ${f.title}`)
        .join("\n")
    : "  None.";

  return `Audit the npm package at ${pkg.path} (${pkg.name}@${pkg.version}).

Read the source code, look for: prototype pollution, ReDoS, path traversal, injection, unsafe deserialization, missing validation. Map data flow from untrusted input to sensitive operations. Report any security findings with severity and PoC suggestions.

Semgrep already found these leads:
${semgrepContext}

npm audit found these advisories:
${npmContext}

For EACH confirmed vulnerability, output a block in this exact format:

---FINDING---
title: <clear title>
severity: <critical|high|medium|low|info>
category: <prototype-pollution|redos|path-traversal|command-injection|code-injection|unsafe-deserialization|ssrf|information-disclosure|missing-validation|other>
description: <detailed description of the vulnerability, how to exploit it, and suggested PoC>
file: <path/to/file.js:lineNumber>
---END---

Output as many ---FINDING--- blocks as needed. Be precise and honest about severity.`;
}

/**
 * Recursively collect source file paths from a directory.
 * Skips node_modules, .git, and binary/image files.
 */
function collectSourceFiles(dir: string, maxFiles = 50): string[] {
  const files: string[] = [];
  const SOURCE_EXTS = new Set([
    ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts",
    ".jsx", ".tsx", ".json", ".yml", ".yaml",
  ]);

  function walk(d: string) {
    if (files.length >= maxFiles) return;
    let entries: string[];
    try {
      entries = readdirSync(d);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (files.length >= maxFiles) return;
      if (entry === "node_modules" || entry === ".git") continue;
      const full = join(d, entry);
      try {
        const st = statSync(full);
        if (st.isDirectory()) {
          walk(full);
        } else if (st.isFile() && st.size < 200_000) {
          const ext = full.slice(full.lastIndexOf("."));
          if (SOURCE_EXTS.has(ext)) {
            files.push(full);
          }
        }
      } catch {
        // skip unreadable
      }
    }
  }

  walk(dir);
  return files;
}

/**
 * Build a prompt that includes the actual source code for direct API analysis.
 */
function buildDirectApiAuditPrompt(
  pkg: InstalledPackage,
  semgrepFindings: SemgrepFinding[],
  npmAuditFindings: NpmAuditFinding[],
): string {
  const sourceFiles = collectSourceFiles(pkg.path);
  const sourceBlocks: string[] = [];
  let totalChars = 0;
  const MAX_CHARS = 150_000; // stay well within context window

  for (const filePath of sourceFiles) {
    if (totalChars >= MAX_CHARS) break;
    try {
      const content = readFileSync(filePath, "utf-8");
      const rel = relative(pkg.path, filePath);
      const block = `--- FILE: ${rel} ---\n${content}\n--- END FILE ---`;
      totalChars += block.length;
      sourceBlocks.push(block);
    } catch {
      // skip unreadable files
    }
  }

  const semgrepContext = semgrepFindings.length > 0
    ? semgrepFindings
        .slice(0, 30)
        .map((f, i) => `  ${i + 1}. [${f.severity}] ${f.ruleId} — ${f.path}:${f.startLine}: ${f.message}`)
        .join("\n")
    : "  None.";

  const npmContext = npmAuditFindings.length > 0
    ? npmAuditFindings
        .slice(0, 30)
        .map((f, i) => `  ${i + 1}. [${f.severity}] ${f.name}: ${f.title}`)
        .join("\n")
    : "  None.";

  return `You are a security researcher performing an authorized source code audit of the npm package "${pkg.name}@${pkg.version}".

## Semgrep findings:
${semgrepContext}

## npm audit advisories:
${npmContext}

## Source code:

${sourceBlocks.join("\n\n")}

## Instructions

Analyze the source code above for security vulnerabilities. Look for:
- Prototype pollution (object merge/extend without hasOwnProperty checks, __proto__ access)
- ReDoS (regex with nested quantifiers, user input in new RegExp())
- Path traversal (user-supplied paths without normalization)
- Command/code injection (exec/eval with user input)
- Unsafe deserialization
- SSRF (HTTP requests with user-controlled URLs)
- Information disclosure (hardcoded credentials, debug modes)
- Missing input validation

For EACH confirmed vulnerability, output a block in this exact format:

---FINDING---
title: <clear title>
severity: <critical|high|medium|low|info>
category: <prototype-pollution|redos|path-traversal|command-injection|code-injection|unsafe-deserialization|ssrf|information-disclosure|missing-validation|other>
description: <detailed description of the vulnerability, how to exploit it, and suggested PoC>
file: <path/to/file.js:lineNumber>
---END---

Output as many ---FINDING--- blocks as needed. If there are no real vulnerabilities, output none.
Be precise and honest about severity — only report real, exploitable issues.`;
}

/**
 * Run an AI agent to analyze semgrep findings and hunt for additional
 * vulnerabilities in the package source code.
 *
 * Delegates to the unified runAnalysisAgent with audit-specific prompts.
 */
async function runAuditAgent(
  pkg: InstalledPackage,
  semgrepFindings: SemgrepFinding[],
  npmAuditFindings: NpmAuditFinding[],
  db: any,
  scanId: string,
  config: AuditConfig,
  emit: ScanListener,
): Promise<{ findings: Finding[]; usage?: { inputTokens: number; outputTokens: number }; estimatedCostUsd?: number }> {
  return runAnalysisAgent({
    role: "audit",
    scopePath: pkg.path,
    target: `npm:${pkg.name}@${pkg.version}`,
    scanId,
    config,
    db,
    emit,
    cliPrompt: buildCliAuditPrompt(pkg, semgrepFindings, npmAuditFindings),
    agentSystemPrompt: auditAgentPrompt(
      pkg.name,
      pkg.version,
      pkg.path,
      semgrepFindings,
      npmAuditFindings,
    ),
    cliSystemPrompt: "You are a security researcher performing an authorized npm package audit. Be thorough and precise. Only report real, exploitable vulnerabilities.",
    directApiPrompt: buildDirectApiAuditPrompt(pkg, semgrepFindings, npmAuditFindings),
  });
}

/**
 * Main entry point: audit an npm package for security vulnerabilities.
 *
 * Pipeline:
 * 1. npm install <package>@latest in a temp dir
 * 2. Run semgrep with security rules
 * 3. AI agent analyzes semgrep findings + hunts for additional vulns
 * 4. Generate report with severity and PoC suggestions
 * 5. Persist to pwnkit DB
 */
export async function packageAudit(
  opts: PackageAuditOptions,
): Promise<AuditReport & { usage?: { inputTokens: number; outputTokens: number }; estimatedCostUsd?: number }> {
  const { config, onEvent } = opts;
  const emit: ScanListener = onEvent ?? (() => {});
  const startTime = Date.now();

  // Step 1: Install package
  const pkg = installPackage(config.package, config.version, emit);

  // Initialize DB and create scan record
  const db = await (async () => { try { const { pwnkitDB } = await import("@pwnkit/db"); return new pwnkitDB(config.dbPath); } catch { return null as any; } })() as any;
  const scanConfig: ScanConfig = {
    target: `npm:${pkg.name}@${pkg.version}`,
    depth: config.depth,
    format: config.format,
    runtime: config.runtime ?? "api",
    mode: "deep",
  };
  const scanId = db?.createScan(scanConfig) ?? "no-db";

  try {
    // Step 2: npm audit + Semgrep scan
    const npmAuditFindings = mergeAdvisories(
      runNpmAudit(pkg.tempDir, emit),
      await queryOsvAdvisories(pkg.name, pkg.version, emit),
    );
    const semgrepFindings = runSemgrepScan(pkg.path, emit, { noGitIgnore: true });
    const advisoryFinding = summarizeKnownAdvisoriesFinding(pkg, npmAuditFindings);

    // Step 2.5: Deterministic malicious-package oracles. These run before
    // the LLM, do not depend on the model, and catch the supply-chain
    // attack patterns the LLM prompt is structurally blind to: typosquats,
    // install-script payloads, credential-theft hooks. Their findings are
    // appended to the report alongside the agent findings.
    emit({
      type: "stage:start",
      stage: "discovery",
      message: "Running deterministic malicious-package oracles...",
    });
    const maliciousFindings = scanForMaliciousPatterns({
      packageName: pkg.name,
      packagePath: pkg.path,
    });
    emit({
      type: "stage:end",
      stage: "discovery",
      message: `Malicious-package oracles: ${maliciousFindings.length} finding${maliciousFindings.length === 1 ? "" : "s"}`,
    });

    // Step 3: AI agent analysis
    const agentResult = await runAuditAgent(
      pkg,
      semgrepFindings,
      npmAuditFindings,
      db,
      scanId,
      config,
      emit,
    );
    const agentFindings = postProcessPackageAuditFindings(agentResult.findings);

    // Combine deterministic + LLM findings into the final report set.
    // Deterministic findings come FIRST so they're prominent in the
    // report ordering — they're higher confidence than LLM output.
    const findings = [
      ...(advisoryFinding ? [advisoryFinding] : []),
      ...maliciousFindings,
      ...agentFindings,
    ];

    // Step 4: Build report
    const durationMs = Date.now() - startTime;
    const summary = {
      totalAttacks: semgrepFindings.length + npmAuditFindings.length,
      totalFindings: findings.length,
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length,
    };

    db?.completeScan(scanId, summary);

    emit({
      type: "stage:end",
      stage: "report",
      message: `Audit complete: ${summary.totalFindings} findings (${npmAuditFindings.length} npm advisories, ${semgrepFindings.length} semgrep findings)`,
    });

    const report: AuditReport & { usage?: { inputTokens: number; outputTokens: number }; estimatedCostUsd?: number } = {
      package: pkg.name,
      version: pkg.version,
      startedAt: new Date(startTime).toISOString(),
      completedAt: new Date().toISOString(),
      durationMs,
      semgrepFindings: semgrepFindings.length,
      npmAuditFindings,
      summary,
      findings,
      usage: agentResult.usage,
      estimatedCostUsd: agentResult.estimatedCostUsd,
    };

    return report;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    db?.failScan(scanId, msg);
    throw err;
  } finally {
    db?.close();
    // Clean up temp directory
    try {
      rmSync(pkg.tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }
}
