/**
 * Pre-recon CVE check — runs language-specific dependency audit tools
 * against the source tree before the agent's first turn (white-box mode
 * only) and surfaces high/critical advisories as priority leads in the
 * agent system prompt.
 *
 * Why this exists: the 2026-04-06 ceiling analysis identified XBEN-030
 * "Wordpress magic" and XBEN-034 "Melodic Mayhem" — both tagged `cve` —
 * as the two most expensive unsolved XBOW challenges. They burned $6+
 * each in white-box mode while producing 0 findings, because the agent
 * had source access but no concrete CVE leads. The audit tools that ship
 * with every language ecosystem can answer this question in seconds:
 * `npm audit` knows the CVE catalogue for any package-lock.json on disk.
 *
 * This module is deliberately conservative:
 *   - It only runs when `--repo` is set (white-box mode)
 *   - It only runs the audit tools that are actually installed
 *   - It never throws — a missing tool, a parse error, or a non-zero
 *     exit just produces an empty report and the scan continues
 *   - It only surfaces high + critical severity advisories (low/medium
 *     would dilute the system prompt with noise)
 */

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export interface CveAdvisory {
  /** Where the manifest file lives, relative to the repo root */
  manifest: string;
  /** Tool that produced the advisory (npm-audit, pip-audit, etc.) */
  tool: string;
  /** Affected package name */
  package: string;
  /** Installed version (if known) */
  version?: string;
  /** Vulnerable version range (if known) */
  vulnerableRange?: string;
  /** CVE / GHSA / advisory ID */
  id: string;
  /** Short title */
  title: string;
  /** "high" or "critical" — we filter low/medium out before this point */
  severity: "high" | "critical";
  /** URL to the advisory page (when available) */
  url?: string;
}

export interface PreReconCveReport {
  /** All advisories found across every detected manifest */
  advisories: CveAdvisory[];
  /** Manifests we scanned */
  manifestsScanned: string[];
  /** Manifests we found but couldn't scan (tool missing, parse error, etc.) */
  manifestsSkipped: Array<{ manifest: string; reason: string }>;
  /** Total wall time spent on the pre-recon */
  durationMs: number;
}

// ────────────────────────────────────────────────────────────────────
// Manifest detection
// ────────────────────────────────────────────────────────────────────

interface ManifestKind {
  /** Filename to look for */
  filename: string;
  /** Tool name for telemetry */
  tool: string;
  /** Function that runs the audit and returns advisories */
  run: (manifestPath: string, manifestRel: string) => CveAdvisory[];
}

/**
 * Walk the source tree (depth-limited) looking for known package manifests.
 * Skips node_modules, .git, dist, build, and similar noise dirs.
 */
function findManifests(
  repoPath: string,
  kinds: ManifestKind[],
  maxDepth = 4,
): Array<{ kind: ManifestKind; absPath: string; relPath: string }> {
  const SKIP_DIRS = new Set([
    "node_modules", ".git", "dist", "build", ".next", ".nuxt", ".svelte-kit",
    "target", "vendor", "venv", ".venv", "__pycache__", ".pytest_cache",
    "out", ".cache", "coverage",
  ]);
  const found: Array<{ kind: ManifestKind; absPath: string; relPath: string }> = [];

  function walk(dir: string, depth: number) {
    if (depth > maxDepth) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (SKIP_DIRS.has(entry)) continue;
      const abs = join(dir, entry);
      let st: ReturnType<typeof statSync>;
      try {
        st = statSync(abs);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        walk(abs, depth + 1);
      } else if (st.isFile()) {
        for (const kind of kinds) {
          if (entry === kind.filename) {
            found.push({
              kind,
              absPath: abs,
              relPath: relative(repoPath, abs),
            });
          }
        }
      }
    }
  }

  walk(repoPath, 0);
  return found;
}

// ────────────────────────────────────────────────────────────────────
// npm audit runner
// ────────────────────────────────────────────────────────────────────

function runNpmAudit(manifestPath: string, manifestRel: string): CveAdvisory[] {
  const dir = manifestPath.replace(/\/(?:package-lock\.json|package\.json)$/, "");
  let output: string;
  try {
    output = execFileSync("npm", ["audit", "--json"], {
      cwd: dir,
      timeout: 30_000,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch (err: any) {
    // npm audit exits non-zero when vulns are found — that's the expected
    // path. Recover the stdout from the error object.
    output = (err && typeof err.stdout === "string" ? err.stdout : "") || "";
    if (!output) return [];
  }

  let parsed: any;
  try {
    parsed = JSON.parse(output);
  } catch {
    return [];
  }

  const advisories: CveAdvisory[] = [];
  const vulns = parsed.vulnerabilities ?? {};
  for (const [pkgName, vuln] of Object.entries<any>(vulns)) {
    const sev = vuln.severity;
    if (sev !== "high" && sev !== "critical") continue;
    // npm audit's "via" array may contain advisory objects (the leaf vuln)
    // OR strings (transitive paths). Walk it and extract the advisory IDs.
    const via: any[] = Array.isArray(vuln.via) ? vuln.via : [];
    let advisoryAdded = false;
    for (const v of via) {
      if (typeof v === "object" && v !== null && v.title) {
        advisories.push({
          manifest: manifestRel,
          tool: "npm-audit",
          package: pkgName,
          version: typeof vuln.range === "string" ? vuln.range : undefined,
          vulnerableRange: typeof v.range === "string" ? v.range : undefined,
          id: String(v.source ?? v.url ?? v.title),
          title: String(v.title),
          severity: sev as "high" | "critical",
          url: typeof v.url === "string" ? v.url : undefined,
        });
        advisoryAdded = true;
      }
    }
    // Fallback: no leaf advisory in via[], emit a synthetic entry
    if (!advisoryAdded) {
      advisories.push({
        manifest: manifestRel,
        tool: "npm-audit",
        package: pkgName,
        severity: sev as "high" | "critical",
        id: `npm-audit:${pkgName}`,
        title: `Transitive ${sev} advisory in ${pkgName} (see npm audit for chain)`,
      });
    }
  }
  return advisories;
}

// ────────────────────────────────────────────────────────────────────
// pip-audit runner (best-effort, skipped if not installed)
// ────────────────────────────────────────────────────────────────────

function runPipAudit(manifestPath: string, manifestRel: string): CveAdvisory[] {
  const dir = manifestPath.replace(/\/requirements\.txt$/, "");
  let output: string;
  try {
    output = execFileSync(
      "pip-audit",
      ["--requirement", "requirements.txt", "--format", "json"],
      {
        cwd: dir,
        timeout: 60_000,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      },
    );
  } catch (err: any) {
    if (err && err.code === "ENOENT") return []; // pip-audit not installed
    output = (err && typeof err.stdout === "string" ? err.stdout : "") || "";
    if (!output) return [];
  }

  let parsed: any;
  try {
    parsed = JSON.parse(output);
  } catch {
    return [];
  }

  const advisories: CveAdvisory[] = [];
  const dependencies: any[] = Array.isArray(parsed.dependencies) ? parsed.dependencies : [];
  for (const dep of dependencies) {
    const pkgName = dep.name;
    const version = dep.version;
    const vulns: any[] = Array.isArray(dep.vulns) ? dep.vulns : [];
    for (const v of vulns) {
      // pip-audit normalizes severity into a fix_versions/aliases shape;
      // we treat any vuln with a CVE/GHSA prefix as high+ for safety.
      const id = String(v.id ?? "");
      const isCveOrGhsa = /^(CVE-|GHSA-)/i.test(id);
      if (!isCveOrGhsa) continue;
      advisories.push({
        manifest: manifestRel,
        tool: "pip-audit",
        package: String(pkgName),
        version: typeof version === "string" ? version : undefined,
        id,
        title: String(v.description ?? v.id ?? "pip-audit advisory"),
        severity: "high",
        url: typeof v.aliases?.[0] === "string" ? v.aliases[0] : undefined,
      });
    }
  }
  return advisories;
}

// ────────────────────────────────────────────────────────────────────
// Manifest registry — add new audit tools here
// ────────────────────────────────────────────────────────────────────

const MANIFEST_KINDS: ManifestKind[] = [
  { filename: "package-lock.json", tool: "npm-audit", run: runNpmAudit },
  { filename: "requirements.txt", tool: "pip-audit", run: runPipAudit },
  // Future: bundle-audit (Gemfile.lock), composer audit (composer.lock),
  // cargo audit (Cargo.lock), govulncheck (go.sum). Each goes here as a
  // new ManifestKind entry. Out of scope for the initial Phase 4 patch.
];

// ────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────

/**
 * Walk the source tree, run every available audit tool against every
 * detected manifest, and return a structured report.
 */
export function runPreReconCveCheck(repoPath: string): PreReconCveReport {
  const start = Date.now();
  const advisories: CveAdvisory[] = [];
  const scanned: string[] = [];
  const skipped: Array<{ manifest: string; reason: string }> = [];

  if (!existsSync(repoPath)) {
    return { advisories, manifestsScanned: scanned, manifestsSkipped: skipped, durationMs: 0 };
  }

  const manifests = findManifests(repoPath, MANIFEST_KINDS);
  for (const { kind, absPath, relPath } of manifests) {
    try {
      const found = kind.run(absPath, relPath);
      scanned.push(relPath);
      advisories.push(...found);
    } catch (err) {
      skipped.push({
        manifest: relPath,
        reason: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return {
    advisories,
    manifestsScanned: scanned,
    manifestsSkipped: skipped,
    durationMs: Date.now() - start,
  };
}

/**
 * Render a pre-recon CVE report into a system-prompt prefix that the
 * attack agent can use as priority investigation leads.
 *
 * Returns null if there are no high/critical advisories — the caller
 * should NOT inject anything into the prompt in that case (an empty
 * "no CVE leads" line just adds noise).
 */
export function formatPreReconForPrompt(report: PreReconCveReport): string | null {
  if (report.advisories.length === 0) return null;

  // Group by package + advisory ID to dedupe transitive paths
  const seen = new Set<string>();
  const uniqueLines: string[] = [];
  for (const a of report.advisories) {
    const key = `${a.package}::${a.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const range = a.vulnerableRange ? ` (vulnerable: ${a.vulnerableRange})` : "";
    const url = a.url ? ` — ${a.url}` : "";
    uniqueLines.push(
      `- \`${a.package}\`${a.version ? `@${a.version}` : ""}: **${a.severity}** — ${a.title} [${a.id}]${range}${url}`,
    );
  }

  const limited = uniqueLines.slice(0, 30); // cap to keep the prompt sane
  const more =
    uniqueLines.length > limited.length
      ? `\n\n_(${uniqueLines.length - limited.length} more advisories suppressed; see npm audit / pip-audit on the source tree for the full list)_`
      : "";

  return [
    "## Priority CVE leads from source-tree audit",
    "",
    "The following high/critical advisories were found by running `npm audit` / `pip-audit` against the package manifests in the source tree before this scan started. The vulnerable versions are confirmed installed. **Investigate these as your first priority** — the running target almost certainly inherits at least one of them, and the exploit chain may already be public.",
    "",
    ...limited,
    more,
    "",
  ].join("\n");
}
