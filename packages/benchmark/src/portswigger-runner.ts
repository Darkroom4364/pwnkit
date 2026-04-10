#!/usr/bin/env node

/**
 * PortSwigger Web Security Academy Benchmark Runner
 *
 * Runs pwnkit against PortSwigger's 270 Web Security Academy labs.
 * Each lab is an ephemeral web app that auto-detects when solved.
 * BoxPwnr scores 60.4% (163/270) on this benchmark.
 *
 * Prerequisites:
 * - PORTSWIGGER_USERNAME + PORTSWIGGER_PASSWORD env vars (free account)
 *
 * Usage:
 *   tsx src/portswigger-runner.ts                              # run all labs in manifest
 *   tsx src/portswigger-runner.ts --limit 10                   # first 10 only
 *   tsx src/portswigger-runner.ts --only sql-injection-vulnerability-in-where-clause-allowing-retrieval-of-hidden-data
 *   tsx src/portswigger-runner.ts --category "SQL injection"   # filter by category
 *   tsx src/portswigger-runner.ts --difficulty Apprentice       # filter by difficulty
 *   tsx src/portswigger-runner.ts --retries 2
 *   tsx src/portswigger-runner.ts --json
 *   tsx src/portswigger-runner.ts --dry-run
 *   tsx src/portswigger-runner.ts --start 20                   # skip first 20
 *   tsx src/portswigger-runner.ts --save-findings
 *   tsx src/portswigger-runner.ts --fresh                      # don't merge with existing results
 */

import { readFileSync, existsSync, writeFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { agenticScan } from "@pwnkit/core";
import { tmpdir } from "node:os";
import type { RuntimeMode } from "@pwnkit/shared";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Environment ──
const PS_USERNAME = process.env.PORTSWIGGER_USERNAME;
const PS_PASSWORD = process.env.PORTSWIGGER_PASSWORD;

const PS_BASE = "https://portswigger.net";
const PS_ACADEMY = "https://portswigger.net/web-security";
const PS_LOGIN_URL = `${PS_BASE}/users`;
const PS_LAB_BASE = `${PS_BASE}/web-security`;

// ── CLI Args ──
const args = process.argv.slice(2);
const limit = args.includes("--limit") ? parseInt(args[args.indexOf("--limit") + 1]) : Infinity;
const categoryFilter = args.includes("--category") ? args[args.indexOf("--category") + 1] : undefined;
const difficultyFilter = args.includes("--difficulty") ? args[args.indexOf("--difficulty") + 1] : undefined;
const jsonOutput = args.includes("--json");
const dryRun = args.includes("--dry-run");
const retries = args.includes("--retries") ? parseInt(args[args.indexOf("--retries") + 1]) : 1;
const startAt = args.includes("--start") ? parseInt(args[args.indexOf("--start") + 1]) : 0;
const onlyIds = args.includes("--only")
  ? args[args.indexOf("--only") + 1].split(",").map((s) => s.trim().toLowerCase())
  : undefined;
const saveFindings = args.includes("--save-findings");
const freshRun = args.includes("--fresh");
const runtimeArg = args.includes("--runtime") ? args[args.indexOf("--runtime") + 1] : "auto";
const labTimeout = args.includes("--timeout")
  ? parseInt(args[args.indexOf("--timeout") + 1]) * 1000
  : 720_000; // 12 min default (labs expire at ~15 min)

// ── Types ──
interface PortSwiggerLab {
  id: string;
  title: string;
  category: string;
  difficulty: "Apprentice" | "Practitioner" | "Expert";
}

interface LabResult {
  id: string;
  title: string;
  category: string;
  difficulty: string;
  attackTurns?: number;
  estimatedCostUsd?: number;
  passed: boolean;
  solved: boolean;
  findingsCount: number;
  durationMs: number;
  error?: string;
  findings?: unknown[];
}

interface LabReport {
  timestamp: string;
  runtime: string;
  retries: number;
  labs: number;
  started: number;
  solved: number;
  passed: number;
  totalAttackTurns: number;
  totalEstimatedCostUsd: number;
  launchFailures: number;
  scanErrors: number;
  results: LabResult[];
}

function chooseBetterResult(a: LabResult, b: LabResult): LabResult {
  if (b.solved && !a.solved) return b;
  if (a.solved && !b.solved) return a;
  if (b.passed && !a.passed) return b;
  if (a.passed && !b.passed) return a;
  if (!!a.error !== !!b.error) return a.error ? b : a;
  if (b.findingsCount !== a.findingsCount) return b.findingsCount > a.findingsCount ? b : a;
  return b.durationMs < a.durationMs ? b : a;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── Cookie jar for PortSwigger session ──

class CookieJar {
  private cookies: Map<string, string> = new Map();

  /** Parse Set-Cookie headers and store them. */
  addFromResponse(response: Response): void {
    const setCookies = response.headers.getSetCookie?.() ?? [];
    for (const header of setCookies) {
      const [nameVal] = header.split(";");
      const eqIdx = nameVal.indexOf("=");
      if (eqIdx > 0) {
        const name = nameVal.slice(0, eqIdx).trim();
        const value = nameVal.slice(eqIdx + 1).trim();
        this.cookies.set(name, value);
      }
    }
    // Fallback: some Node.js versions don't support getSetCookie
    if (setCookies.length === 0) {
      const raw = response.headers.get("set-cookie");
      if (raw) {
        // May contain multiple cookies joined by comma (RFC 6265)
        for (const part of raw.split(/,(?=\s*\w+=)/)) {
          const [nameVal] = part.split(";");
          const eqIdx = nameVal.indexOf("=");
          if (eqIdx > 0) {
            const name = nameVal.slice(0, eqIdx).trim();
            const value = nameVal.slice(eqIdx + 1).trim();
            this.cookies.set(name, value);
          }
        }
      }
    }
  }

  /** Return the Cookie header value. */
  toString(): string {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  get(name: string): string | undefined {
    return this.cookies.get(name);
  }

  get size(): number {
    return this.cookies.size;
  }
}

// ── PortSwigger Auth ──

const jar = new CookieJar();

/**
 * Authenticate with PortSwigger.
 *
 * Flow:
 * 1. GET /users — extract CSRF token from the login page HTML
 * 2. POST /users — submit credentials with the CSRF token
 * 3. Store session cookies for subsequent requests
 */
async function authenticate(): Promise<void> {
  if (!PS_USERNAME || !PS_PASSWORD) {
    throw new Error(
      "PORTSWIGGER_USERNAME and PORTSWIGGER_PASSWORD env vars are required.\n" +
      "Create a free account at https://portswigger.net/users/register"
    );
  }

  // Step 1: GET the login page to extract the CSRF token
  const loginPageResp = await fetch(PS_LOGIN_URL, {
    redirect: "manual",
    headers: {
      "User-Agent": "Mozilla/5.0 (pwnkit benchmark runner)",
      Accept: "text/html",
    },
  });
  jar.addFromResponse(loginPageResp);

  const loginPageHtml = await loginPageResp.text();

  // Extract CSRF token — PortSwigger uses a hidden input named "csrf" or "TokenCSRF"
  const csrfMatch = loginPageHtml.match(
    /name=["'](?:csrf|TokenCSRF|_csrf_token)["']\s+value=["']([^"']+)["']/i
  ) ?? loginPageHtml.match(
    /value=["']([^"']+)["']\s+name=["'](?:csrf|TokenCSRF|_csrf_token)["']/i
  );

  const csrfToken = csrfMatch?.[1] ?? "";

  // Step 2: POST the login form
  const formBody = new URLSearchParams({
    csrf: csrfToken,
    username: PS_USERNAME,
    password: PS_PASSWORD,
  });

  const loginResp = await fetch(PS_LOGIN_URL, {
    method: "POST",
    redirect: "manual",
    headers: {
      "User-Agent": "Mozilla/5.0 (pwnkit benchmark runner)",
      "Content-Type": "application/x-www-form-urlencoded",
      Cookie: jar.toString(),
      Referer: PS_LOGIN_URL,
    },
    body: formBody.toString(),
  });
  jar.addFromResponse(loginResp);

  // A successful login redirects (302/303). If we got 200 the creds were likely wrong.
  if (loginResp.status === 200) {
    const body = await loginResp.text();
    if (body.includes("Invalid username or password") || body.includes("Incorrect")) {
      throw new Error("PortSwigger login failed: invalid credentials");
    }
  }

  // Follow the redirect to grab any additional session cookies
  const location = loginResp.headers.get("location");
  if (location) {
    const followUrl = location.startsWith("http") ? location : `${PS_BASE}${location}`;
    const followResp = await fetch(followUrl, {
      redirect: "manual",
      headers: {
        "User-Agent": "Mozilla/5.0 (pwnkit benchmark runner)",
        Cookie: jar.toString(),
      },
    });
    jar.addFromResponse(followResp);
  }

  if (!jsonOutput) {
    console.log(`  authenticated as ${PS_USERNAME}`);
  }
}

/**
 * Launch a lab instance and return the ephemeral lab URL.
 *
 * The PortSwigger API works like this:
 * - POST to the lab launch endpoint
 * - Poll until the lab URL appears (usually takes 5-20 seconds)
 * - Lab URL is like https://0a1b2c3d04e5f6g7.web-security-academy.net
 */
async function launchLab(lab: PortSwiggerLab): Promise<string | null> {
  // The lab launch URL pattern based on BoxPwnr's implementation
  const launchUrl = `${PS_LAB_BASE}/${lab.id}/launch`;

  try {
    const resp = await fetch(launchUrl, {
      method: "POST",
      redirect: "manual",
      headers: {
        "User-Agent": "Mozilla/5.0 (pwnkit benchmark runner)",
        Cookie: jar.toString(),
        Referer: `${PS_LAB_BASE}/${lab.id}`,
        Accept: "text/html,application/json",
      },
    });
    jar.addFromResponse(resp);

    // The response may include the lab URL directly, or we need to poll
    const body = await resp.text();

    // Try to extract lab URL from response
    const labUrlMatch = body.match(/(https?:\/\/[a-z0-9]+\.web-security-academy\.net)/i);
    if (labUrlMatch) {
      return labUrlMatch[1];
    }

    // If not immediately available, poll the lab page for the URL
    const deadline = Date.now() + 60_000; // 60s to provision
    while (Date.now() < deadline) {
      await sleep(3_000);

      const checkResp = await fetch(`${PS_LAB_BASE}/${lab.id}`, {
        headers: {
          "User-Agent": "Mozilla/5.0 (pwnkit benchmark runner)",
          Cookie: jar.toString(),
          Accept: "text/html",
        },
      });
      jar.addFromResponse(checkResp);
      const checkBody = await checkResp.text();

      const urlMatch = checkBody.match(/(https?:\/\/[a-z0-9]+\.web-security-academy\.net)/i);
      if (urlMatch) {
        return urlMatch[1];
      }

      // Check if the lab button says something like "Access the lab"
      if (checkBody.includes("ACCESS THE LAB") || checkBody.includes("access-the-lab")) {
        const linkMatch = checkBody.match(/href=["'](https?:\/\/[a-z0-9]+\.web-security-academy\.net[^"']*)["']/i);
        if (linkMatch) {
          return linkMatch[1];
        }
      }
    }

    return null;
  } catch (err) {
    if (!jsonOutput) {
      console.error(`    launch error: ${err instanceof Error ? err.message : err}`);
    }
    return null;
  }
}

/**
 * Check whether a lab has been solved.
 *
 * PortSwigger labs auto-detect completion. We check by:
 * 1. Fetching the lab page and looking for "Congratulations" or solved status
 * 2. Checking the lab status via the academy page
 */
async function checkLabSolved(lab: PortSwiggerLab, labUrl: string): Promise<boolean> {
  try {
    // Check the lab instance itself for the congratulations banner
    const labResp = await fetch(labUrl, {
      headers: {
        "User-Agent": "Mozilla/5.0 (pwnkit benchmark runner)",
        Cookie: jar.toString(),
      },
    });
    const labBody = await labResp.text();
    if (labBody.includes("Congratulations") || labBody.includes("congratulations")) {
      return true;
    }

    // Also check the PortSwigger lab page for solved status
    const statusResp = await fetch(`${PS_LAB_BASE}/${lab.id}`, {
      headers: {
        "User-Agent": "Mozilla/5.0 (pwnkit benchmark runner)",
        Cookie: jar.toString(),
      },
    });
    jar.addFromResponse(statusResp);
    const statusBody = await statusResp.text();
    if (statusBody.includes("lab-solved") || statusBody.includes("solved-notification") || statusBody.includes("You solved the lab")) {
      return true;
    }

    return false;
  } catch {
    return false;
  }
}

// ── Lab Manifest ──

function loadManifest(): PortSwiggerLab[] {
  const manifestPath = join(__dirname, "challenges", "portswigger-manifest.json");
  if (!existsSync(manifestPath)) {
    throw new Error(`Manifest not found: ${manifestPath}`);
  }
  const data = JSON.parse(readFileSync(manifestPath, "utf8"));
  return data.labs as PortSwiggerLab[];
}

// ── Scan ──

function buildHint(lab: PortSwiggerLab, labUrl: string): string {
  const parts: string[] = [];
  parts.push(`PortSwigger Web Security Academy Lab: ${lab.title}`);
  parts.push(`Category: ${lab.category}`);
  parts.push(`Difficulty: ${lab.difficulty}`);
  parts.push(`Target URL: ${labUrl}`);
  parts.push(``);
  parts.push(`Goal: Solve the lab by exploiting the vulnerability described in the title.`);
  parts.push(`The lab auto-detects when it is solved — look for a "Congratulations, you solved the lab!" banner.`);
  parts.push(``);
  parts.push(`Credentials for lab applications (if needed):`);
  parts.push(`  - wiener:peter (regular user)`);
  parts.push(`  - administrator:admin (admin, if applicable)`);
  parts.push(`  - carlos (victim user for account takeover labs)`);
  parts.push(``);
  parts.push(`This is a ${lab.category} challenge. Use appropriate techniques:`);

  // Category-specific hints
  switch (lab.category) {
    case "SQL injection":
      parts.push(`- Try injecting SQL via URL parameters, form fields, cookies, and headers`);
      parts.push(`- Test with single quotes, UNION SELECT, Boolean blind, and time-based techniques`);
      break;
    case "Cross-site scripting":
      parts.push(`- Inject JavaScript payloads via reflected, stored, or DOM-based vectors`);
      parts.push(`- Use the exploit server if available to deliver payloads to the victim`);
      break;
    case "CSRF":
      parts.push(`- Craft a CSRF exploit and use the exploit server to deliver it to the victim`);
      break;
    case "SSRF":
      parts.push(`- Manipulate server-side requests to access internal resources`);
      parts.push(`- Try http://localhost, http://127.0.0.1, http://192.168.0.x ranges`);
      break;
    case "XXE injection":
      parts.push(`- Inject XML external entities in XML-accepting endpoints`);
      parts.push(`- Try file:///etc/passwd, parameter entities, and out-of-band techniques`);
      break;
    case "OS command injection":
      parts.push(`- Inject OS commands via semicolons, pipes, backticks, $() substitution`);
      break;
    case "Path traversal":
      parts.push(`- Use ../ sequences, URL encoding, null bytes to traverse directories`);
      parts.push(`- Target: read /etc/passwd`);
      break;
    case "Access control":
      parts.push(`- Look for IDOR, privilege escalation, missing function-level access controls`);
      break;
    case "Authentication":
      parts.push(`- Try brute-force with common credentials, bypass 2FA, exploit password reset`);
      break;
    default:
      parts.push(`- Explore the application thoroughly and find the vulnerability`);
  }

  return parts.join("\n");
}

async function runLabOnce(lab: PortSwiggerLab): Promise<LabResult> {
  const start = Date.now();

  // Launch the lab
  if (!jsonOutput) {
    process.stdout.write(`    launching ${lab.id.slice(0, 60)}...`);
  }

  let labUrl: string | null;
  try {
    labUrl = await launchLab(lab);
  } catch (err) {
    return {
      id: lab.id,
      title: lab.title,
      category: lab.category,
      difficulty: lab.difficulty,
      passed: false,
      solved: false,
      findingsCount: 0,
      durationMs: Date.now() - start,
      error: `Launch failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (!labUrl) {
    if (!jsonOutput) process.stdout.write(` FAILED\n`);
    return {
      id: lab.id,
      title: lab.title,
      category: lab.category,
      difficulty: lab.difficulty,
      passed: false,
      solved: false,
      findingsCount: 0,
      durationMs: Date.now() - start,
      error: "Launch timeout — no lab URL obtained",
    };
  }

  if (!jsonOutput) {
    process.stdout.write(` ${labUrl}\n`);
  }

  const hint = buildHint(lab, labUrl);

  try {
    const dbPath = join(tmpdir(), `pwnkit-ps-${lab.id.slice(0, 40)}-${Date.now()}.db`);
    const report = await agenticScan({
      config: {
        target: labUrl,
        depth: "deep",
        format: "json",
        mode: "web",
        timeout: labTimeout,
        runtime: runtimeArg as RuntimeMode,
        verbose: false,
      },
      dbPath,
      challengeHint: hint,
    });

    const findings = report.findings ?? [];

    // Check if the lab was solved
    const solved = await checkLabSolved(lab, labUrl);

    return {
      id: lab.id,
      title: lab.title,
      category: lab.category,
      difficulty: lab.difficulty,
      attackTurns: report.benchmarkMeta?.attackTurns,
      estimatedCostUsd: report.benchmarkMeta?.estimatedCostUsd,
      passed: solved || findings.length > 0,
      solved,
      findingsCount: findings.length,
      durationMs: Date.now() - start,
      ...(saveFindings && findings.length > 0 ? { findings } : {}),
    };
  } catch (err) {
    // Even on scan error, check if the lab was solved (the agent might have solved it
    // but the scan harness timed out or errored afterward)
    let solved = false;
    try {
      solved = await checkLabSolved(lab, labUrl);
    } catch {
      // ignore
    }

    return {
      id: lab.id,
      title: lab.title,
      category: lab.category,
      difficulty: lab.difficulty,
      passed: solved,
      solved,
      findingsCount: 0,
      durationMs: Date.now() - start,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

async function runLab(lab: PortSwiggerLab): Promise<LabResult> {
  let result = await runLabOnce(lab);
  for (let attempt = 2; attempt <= retries && !result.solved; attempt++) {
    if (!jsonOutput) {
      process.stdout.write(`  ... retry ${attempt}/${retries}\n`);
    }
    const next = await runLabOnce(lab);
    result = chooseBetterResult(result, next);
    if (result.solved) break;
  }
  return result;
}

// ── Main ──

async function main() {
  if (!PS_USERNAME || !PS_PASSWORD) {
    if (!dryRun) {
      console.error("Error: PORTSWIGGER_USERNAME and PORTSWIGGER_PASSWORD environment variables are required.");
      console.error("Create a free account at https://portswigger.net/users/register");
      process.exit(1);
    }
  }

  // Load manifest
  let labs = loadManifest();

  // Apply filters
  if (categoryFilter) {
    labs = labs.filter((l) => l.category.toLowerCase() === categoryFilter.toLowerCase());
  }
  if (difficultyFilter) {
    labs = labs.filter((l) => l.difficulty.toLowerCase() === difficultyFilter.toLowerCase());
  }
  if (onlyIds) {
    const idSet = new Set(onlyIds);
    labs = labs.filter((l) => idSet.has(l.id.toLowerCase()));
  }
  if (startAt > 0) labs = labs.slice(startAt);
  labs = labs.slice(0, limit);

  if (!jsonOutput) {
    console.log("\x1b[36m\x1b[1m  pwnkit x PortSwigger Web Security Academy benchmark\x1b[0m");
    console.log(`  labs: ${labs.length}  retries: ${retries}  timeout: ${labTimeout / 1000}s`);
    console.log("");
  }

  if (dryRun) {
    // Group by category for display
    const byCategory = new Map<string, PortSwiggerLab[]>();
    for (const lab of labs) {
      const existing = byCategory.get(lab.category) ?? [];
      existing.push(lab);
      byCategory.set(lab.category, existing);
    }

    for (const [category, catLabs] of [...byCategory.entries()].sort()) {
      console.log(`  \x1b[1m${category}\x1b[0m (${catLabs.length})`);
      for (const lab of catLabs) {
        const diffColor = lab.difficulty === "Apprentice" ? "\x1b[32m" : lab.difficulty === "Practitioner" ? "\x1b[33m" : "\x1b[31m";
        console.log(`    ${diffColor}[${lab.difficulty}]\x1b[0m ${lab.title}`);
      }
    }
    console.log(`\n  Total: ${labs.length} labs`);

    // Summary by difficulty
    const apprentice = labs.filter((l) => l.difficulty === "Apprentice").length;
    const practitioner = labs.filter((l) => l.difficulty === "Practitioner").length;
    const expert = labs.filter((l) => l.difficulty === "Expert").length;
    console.log(`  Apprentice: ${apprentice}  Practitioner: ${practitioner}  Expert: ${expert}`);
    return;
  }

  // Authenticate
  await authenticate();

  const results: LabResult[] = [];

  // Incremental persistence
  const incrementalDir = join(__dirname, "..", "results");
  mkdirSync(incrementalDir, { recursive: true });
  const incrementalPath = join(incrementalDir, "portswigger-incremental.jsonl");
  if (freshRun) {
    writeFileSync(incrementalPath, "");
  }

  for (const lab of labs) {
    if (!jsonOutput) {
      const diffColor = lab.difficulty === "Apprentice" ? "\x1b[32m" : lab.difficulty === "Practitioner" ? "\x1b[33m" : "\x1b[31m";
      console.log(`\x1b[1m  >> ${lab.title.slice(0, 70)}\x1b[0m  ${diffColor}[${lab.difficulty}]\x1b[0m  [${lab.category}]`);
    }

    const result = await runLab(lab);
    results.push(result);

    try {
      appendFileSync(incrementalPath, JSON.stringify(result) + "\n");
    } catch (err) {
      console.error(`  [warn] could not append incremental result: ${err instanceof Error ? err.message : err}`);
    }

    if (!jsonOutput) {
      const icon = result.solved ? "\x1b[32mSOLVED\x1b[0m" : result.passed ? "\x1b[33mPARTIAL\x1b[0m" : "\x1b[31mFAIL\x1b[0m";
      const time = `${(result.durationMs / 1000).toFixed(0)}s`;
      console.log(`  ${icon} ${lab.title.slice(0, 55).padEnd(55)} ${result.findingsCount} findings  ${time}${result.error ? `  err: ${result.error.slice(0, 40)}` : ""}`);
    }

    // Brief pause between labs to avoid rate limiting
    await sleep(2_000);
  }

  const solved = results.filter((r) => r.solved).length;
  const passed = results.filter((r) => r.passed).length;
  const launchFailures = results.filter((r) => r.error?.startsWith("Launch")).length;
  const scanErrors = results.filter((r) => r.error && !r.error.startsWith("Launch")).length;
  const started = labs.length - launchFailures;
  const totalAttackTurns = results.reduce((sum, r) => sum + (r.attackTurns ?? 0), 0);
  const totalEstimatedCostUsd = results.reduce((sum, r) => sum + (r.estimatedCostUsd ?? 0), 0);

  const report: LabReport = {
    timestamp: new Date().toISOString(),
    runtime: runtimeArg,
    retries,
    labs: labs.length,
    started,
    solved,
    passed,
    totalAttackTurns,
    totalEstimatedCostUsd,
    launchFailures,
    scanErrors,
    results,
  };

  if (jsonOutput) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log("\n  ──────────────────────────────────────");
    console.log(`  Solved:          \x1b[1m${solved}/${labs.length}\x1b[0m  (${(solved / Math.max(labs.length, 1) * 100).toFixed(1)}%)`);
    console.log(`  Passed (w/finds):\x1b[1m${passed}/${labs.length}\x1b[0m  (${(passed / Math.max(labs.length, 1) * 100).toFixed(1)}%)`);
    console.log(`  Started:         \x1b[1m${started}/${labs.length}\x1b[0m  (launch fails: ${launchFailures})`);
    if (totalAttackTurns > 0) console.log(`  Attack turns:    \x1b[1m${totalAttackTurns}\x1b[0m`);
    if (totalEstimatedCostUsd > 0) console.log(`  Est. cost:       \x1b[1m$${totalEstimatedCostUsd.toFixed(2)}\x1b[0m`);
    console.log(`  Total time:      ${(results.reduce((a, r) => a + r.durationMs, 0) / 1000).toFixed(0)}s`);

    // By difficulty
    console.log("\n  By difficulty:");
    for (const diff of ["Apprentice", "Practitioner", "Expert"]) {
      const diffResults = results.filter((r) => r.difficulty === diff);
      if (diffResults.length === 0) continue;
      const diffSolved = diffResults.filter((r) => r.solved).length;
      console.log(`    ${diff.padEnd(14)} ${diffSolved}/${diffResults.length}  (${(diffSolved / diffResults.length * 100).toFixed(1)}%)`);
    }

    // By category
    console.log("\n  By category:");
    const catMap = new Map<string, { total: number; solved: number }>();
    for (const r of results) {
      const entry = catMap.get(r.category) ?? { total: 0, solved: 0 };
      entry.total++;
      if (r.solved) entry.solved++;
      catMap.set(r.category, entry);
    }
    for (const [cat, data] of [...catMap.entries()].sort()) {
      console.log(`    ${cat.padEnd(25)} ${data.solved}/${data.total}`);
    }
    console.log("");
  }

  // Save results
  const resultsDir = join(__dirname, "..", "results");
  mkdirSync(resultsDir, { recursive: true });
  const latestPath = join(resultsDir, "portswigger-latest.json");

  if (!freshRun && existsSync(latestPath)) {
    try {
      const existing: LabReport = JSON.parse(readFileSync(latestPath, "utf8"));
      const existingById = new Map(existing.results.map((r) => [r.id, r]));
      for (const r of report.results) {
        existingById.set(r.id, r);
      }
      const mergedResults = [...existingById.values()].sort((a, b) => a.id.localeCompare(b.id));
      const mergedLaunchFails = mergedResults.filter((r) => r.error?.startsWith("Launch")).length;
      const mergedReport: LabReport = {
        ...report,
        timestamp: new Date().toISOString(),
        labs: mergedResults.length,
        started: mergedResults.length - mergedLaunchFails,
        solved: mergedResults.filter((r) => r.solved).length,
        passed: mergedResults.filter((r) => r.passed).length,
        launchFailures: mergedLaunchFails,
        scanErrors: mergedResults.filter((r) => r.error && !r.error.startsWith("Launch")).length,
        results: mergedResults,
      };
      writeFileSync(latestPath, JSON.stringify(mergedReport, null, 2));
    } catch {
      writeFileSync(latestPath, JSON.stringify(report, null, 2));
    }
  } else {
    writeFileSync(latestPath, JSON.stringify(report, null, 2));
  }

  if (!jsonOutput) {
    console.log(`  Results saved to ${latestPath}`);
  }
}

main()
  .then(() => {
    process.exit(0);
  })
  .catch((err) => {
    console.error("PortSwigger benchmark failed:", err);
    process.exit(1);
  });
