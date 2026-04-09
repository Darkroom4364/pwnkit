#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);

const repo = args.includes("--repo") ? args[args.indexOf("--repo") + 1] : "PwnKit-Labs/pwnkit";
const workflow = args.includes("--workflow") ? args[args.indexOf("--workflow") + 1] : "xbow-bench.yml";
const limitRuns = args.includes("--limit-runs") ? parseInt(args[args.indexOf("--limit-runs") + 1], 10) : 50;
const outputPath = args.includes("--output")
  ? args[args.indexOf("--output") + 1]
  : join(__dirname, "..", "..", "results", "xbow-canonical.json");

interface RunSummary {
  databaseId: number;
  status: string;
  conclusion: string;
  createdAt: string;
  updatedAt: string;
  url: string;
}

interface XbowResult {
  id: string;
  flagFound?: boolean;
  error?: string;
}

interface XbowReport {
  timestamp?: string;
  runtime?: string;
  whiteBox?: boolean;
  retries?: number;
  challenges?: number;
  flags?: number;
  results?: XbowResult[];
}

interface SolvedSource {
  runId: number;
  url: string;
  createdAt: string;
  artifact: string;
  whiteBox: boolean;
  retries: number | null;
  runtime: string | null;
}

function ghJson<T>(argv: string[]): T {
  const output = execFileSync("gh", argv, {
    encoding: "utf-8",
    stdio: ["pipe", "pipe", "pipe"],
    maxBuffer: 10 * 1024 * 1024,
  });
  return JSON.parse(output) as T;
}

function walk(dir: string): string[] {
  const entries = readdirSync(dir);
  const files: string[] = [];
  for (const entry of entries) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) files.push(...walk(full));
    else files.push(full);
  }
  return files;
}

function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort();
}

function sortedEntries(map: Map<string, SolvedSource[]>): Record<string, SolvedSource[]> {
  return Object.fromEntries(
    [...map.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => [
        k,
        v.sort((a, b) => a.createdAt.localeCompare(b.createdAt) || a.runId - b.runId),
      ]),
  );
}

const runs = ghJson<RunSummary[]>([
  "run",
  "list",
  "--repo",
  repo,
  "--workflow",
  workflow,
  "--limit",
  String(limitRuns),
  "--json",
  "databaseId,status,conclusion,createdAt,updatedAt,url",
]).filter((run) => run.status === "completed" && run.conclusion === "success");

const blackBoxSolved = new Map<string, SolvedSource[]>();
const whiteBoxSolved = new Map<string, SolvedSource[]>();
const skippedRuns: Array<{ runId: number; reason: string }> = [];

for (const run of runs) {
  const downloadDir = mkdtempSync(join(tmpdir(), "pwnkit-xbow-consolidate-"));
  try {
    execFileSync(
      "gh",
      ["run", "download", String(run.databaseId), "--repo", repo, "-D", downloadDir],
      {
        stdio: ["pipe", "pipe", "pipe"],
        maxBuffer: 50 * 1024 * 1024,
      },
    );
  } catch (err) {
    skippedRuns.push({
      runId: run.databaseId,
      reason: err instanceof Error ? err.message : String(err),
    });
    continue;
  }

  const reportFiles = walk(downloadDir).filter((file) => basename(file) === "xbow-latest.json");
  if (reportFiles.length === 0) {
    skippedRuns.push({ runId: run.databaseId, reason: "no xbow-latest.json artifact found" });
    continue;
  }

  for (const file of reportFiles) {
    const report = JSON.parse(readFileSync(file, "utf8")) as XbowReport;
    const solvedMap = report.whiteBox ? whiteBoxSolved : blackBoxSolved;
    const artifact = basename(dirname(file));

    for (const result of report.results ?? []) {
      if (!result.flagFound) continue;
      const sources = solvedMap.get(result.id) ?? [];
      sources.push({
        runId: run.databaseId,
        url: run.url,
        createdAt: run.createdAt,
        artifact,
        whiteBox: !!report.whiteBox,
        retries: report.retries ?? null,
        runtime: report.runtime ?? null,
      });
      solvedMap.set(result.id, sources);
    }
  }
}

const blackIds = uniqueSorted(blackBoxSolved.keys());
const whiteIds = uniqueSorted(whiteBoxSolved.keys());
const aggregateIds = uniqueSorted([...blackIds, ...whiteIds]);
const whiteOnlyIds = whiteIds.filter((id) => !blackBoxSolved.has(id));

const canonical = {
  generatedAt: new Date().toISOString(),
  repo,
  workflow,
  runWindow: {
    limitRuns,
    successfulRunsConsidered: runs.length,
    skippedRuns,
  },
  counts: {
    blackBox: blackIds.length,
    whiteBox: whiteIds.length,
    aggregate: aggregateIds.length,
    whiteBoxOnly: whiteOnlyIds.length,
  },
  solved: {
    blackBox: blackIds,
    whiteBox: whiteIds,
    aggregate: aggregateIds,
    whiteBoxOnly: whiteOnlyIds,
  },
  sources: {
    blackBox: sortedEntries(blackBoxSolved),
    whiteBox: sortedEntries(whiteBoxSolved),
  },
};

mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(canonical, null, 2) + "\n");

console.log(`Wrote ${outputPath}`);
console.log(`  black-box solved:   ${blackIds.length}`);
console.log(`  white-box solved:   ${whiteIds.length}`);
console.log(`  aggregate solved:   ${aggregateIds.length}`);
console.log(`  white-box only:     ${whiteOnlyIds.length}`);
