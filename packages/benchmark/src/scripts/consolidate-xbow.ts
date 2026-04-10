#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, readdirSync, statSync, rmSync } from "node:fs";
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
  model?: string;
}

interface XbowReport {
  timestamp?: string;
  runtime?: string;
  model?: string;
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
  model: string | null;
}

interface ArtifactSummary {
  id: number;
  name: string;
  expired: boolean;
  created_at: string;
  archive_download_url: string;
  workflow_run?: {
    id: number;
  };
}

interface ArtifactPage {
  total_count?: number;
  artifacts?: ArtifactSummary[];
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

function fetchXbowArtifacts(
  repoName: string,
  runIds: Set<number>,
  oldestRunCreatedAt: string,
): ArtifactSummary[] {
  const matches: ArtifactSummary[] = [];
  const oldestMs = Date.parse(oldestRunCreatedAt);

  for (let page = 1; page <= 10; page += 1) {
    const payload = ghJson<ArtifactPage>([
      "api",
      `repos/${repoName}/actions/artifacts?per_page=100&page=${page}`,
    ]);
    const artifacts = payload.artifacts ?? [];
    if (artifacts.length === 0) break;

    for (const artifact of artifacts) {
      if (!artifact.name.startsWith("xbow-results-")) continue;
      if (artifact.expired) continue;
      if (!artifact.workflow_run?.id || !runIds.has(artifact.workflow_run.id)) continue;
      matches.push(artifact);
    }

    const last = artifacts[artifacts.length - 1];
    if (!last) break;
    const lastMs = Date.parse(last.created_at);
    if (Number.isFinite(oldestMs) && Number.isFinite(lastMs) && lastMs < oldestMs) {
      break;
    }
  }

  return matches;
}

function downloadArtifact(repoName: string, artifact: ArtifactSummary, outputDir: string): string[] {
  const zipPath = join(outputDir, `${artifact.id}.zip`);
  const extractDir = join(outputDir, String(artifact.id));
  mkdirSync(extractDir, { recursive: true });

  const zipBuffer = execFileSync(
    "gh",
    ["api", `repos/${repoName}/actions/artifacts/${artifact.id}/zip`],
    {
      stdio: ["pipe", "pipe", "pipe"],
      maxBuffer: 100 * 1024 * 1024,
      encoding: "buffer",
    },
  );
  writeFileSync(zipPath, zipBuffer);
  execFileSync("unzip", ["-qq", zipPath, "-d", extractDir], {
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 100 * 1024 * 1024,
  });
  rmSync(zipPath, { force: true });
  return walk(extractDir).filter((file) => basename(file) === "xbow-latest.json");
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
]).filter((run) => run.status === "completed");
const runsById = new Map(runs.map((run) => [run.databaseId, run] as const));
const xbowArtifacts = runs.length > 0
  ? fetchXbowArtifacts(
      repo,
      new Set(runs.map((run) => run.databaseId)),
      runs[runs.length - 1]!.createdAt,
    )
  : [];
const artifactsByRunId = new Map<number, ArtifactSummary[]>();
for (const artifact of xbowArtifacts) {
  const runId = artifact.workflow_run?.id;
  if (!runId) continue;
  const list = artifactsByRunId.get(runId) ?? [];
  list.push(artifact);
  artifactsByRunId.set(runId, list);
}

const blackBoxSolved = new Map<string, SolvedSource[]>();
const whiteBoxSolved = new Map<string, SolvedSource[]>();
const skippedRuns: Array<{ runId: number; reason: string }> = [];

// Per-model tracking: for each model, track which challenge IDs were
// attempted and which were solved (flag found). A challenge counts as
// "attempted by model X" if any run ever produced a result for it with
// that model. It counts as "solved" if any such result had flagFound.
interface PerModelStats {
  attempted: Set<string>;
  solved: Set<string>;
}
const perModelStats = new Map<string, PerModelStats>();

function trackModelResult(model: string, challengeId: string, flagFound: boolean): void {
  let stats = perModelStats.get(model);
  if (!stats) {
    stats = { attempted: new Set(), solved: new Set() };
    perModelStats.set(model, stats);
  }
  stats.attempted.add(challengeId);
  if (flagFound) stats.solved.add(challengeId);
}

for (const run of runs) {
  const downloadDir = mkdtempSync(join(tmpdir(), "pwnkit-xbow-consolidate-"));
  const artifacts = artifactsByRunId.get(run.databaseId) ?? [];
  if (artifacts.length === 0) {
    skippedRuns.push({ runId: run.databaseId, reason: "no xbow-results artifact found" });
    continue;
  }

  let reportFiles: string[] = [];
  try {
    for (const artifact of artifacts) {
      reportFiles = reportFiles.concat(downloadArtifact(repo, artifact, downloadDir));
    }
  } catch (err) {
    skippedRuns.push({
      runId: run.databaseId,
      reason: err instanceof Error ? err.message : String(err),
    });
    continue;
  }

  if (reportFiles.length === 0) {
    skippedRuns.push({ runId: run.databaseId, reason: "no xbow-latest.json artifact found" });
    continue;
  }

  for (const file of reportFiles) {
    const report = JSON.parse(readFileSync(file, "utf8")) as XbowReport;
    const solvedMap = report.whiteBox ? whiteBoxSolved : blackBoxSolved;
    const artifact = basename(dirname(file));

    for (const result of report.results ?? []) {
      // Track per-model stats for every result, not just solved ones.
      const resultModel = result.model ?? report.model ?? "unknown";
      trackModelResult(resultModel, result.id, !!result.flagFound);

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
        model: result.model ?? report.model ?? null,
      });
      solvedMap.set(result.id, sources);
    }
  }
}

const blackIds = uniqueSorted(blackBoxSolved.keys());
const whiteIds = uniqueSorted(whiteBoxSolved.keys());
const aggregateIds = uniqueSorted([...blackIds, ...whiteIds]);
const whiteOnlyIds = whiteIds.filter((id) => !blackBoxSolved.has(id));

// Build per-model breakdown sorted by solve rate descending
const perModel: Record<string, { solved: number; attempted: number; rate: number; challengesSolved: string[] }> =
  Object.fromEntries(
    [...perModelStats.entries()]
      .map(([model, stats]) => {
        const solved = stats.solved.size;
        const attempted = stats.attempted.size;
        const rate = attempted > 0 ? Math.round((solved / attempted) * 1000) / 10 : 0;
        return [model, { solved, attempted, rate, challengesSolved: uniqueSorted(stats.solved) }] as const;
      })
      .sort(([, a], [, b]) => b.rate - a.rate || b.solved - a.solved),
  );

const canonical = {
  generatedAt: new Date().toISOString(),
  repo,
  workflow,
  runWindow: {
    limitRuns,
    completedRunsConsidered: runs.length,
    xbowArtifactsConsidered: xbowArtifacts.length,
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
  perModel,
};

mkdirSync(dirname(outputPath), { recursive: true });
writeFileSync(outputPath, JSON.stringify(canonical, null, 2) + "\n");

console.log(`Wrote ${outputPath}`);
console.log(`  black-box solved:   ${blackIds.length}`);
console.log(`  white-box solved:   ${whiteIds.length}`);
console.log(`  aggregate solved:   ${aggregateIds.length}`);
console.log(`  white-box only:     ${whiteOnlyIds.length}`);

if (Object.keys(perModel).length > 0) {
  console.log(`\n  Per-model breakdown:`);
  for (const [model, stats] of Object.entries(perModel)) {
    console.log(`    ${model}: ${stats.solved}/${stats.attempted} (${stats.rate}%)`);
  }
}
