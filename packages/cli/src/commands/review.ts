import type { Command } from "commander";
import type { ScanDepth, OutputFormat, RuntimeMode } from "@pwnkit/shared";
import { runUnified } from "./run.js";

export function registerReviewCommand(program: Command): void {
  program
    .command("review")
    .description("Deep source code security review of a repository")
    .argument("<repo>", "Local path or git URL to review")
    .option("--depth <depth>", "Review depth: quick, default, deep", "default")
    .option("--format <format>", "Output format: terminal, json, md, html, sarif, pdf", "terminal")
    .option("--runtime <runtime>", "Runtime: auto, claude, codex, gemini, api", "auto")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--api-key <key>", "API key for LLM provider")
    .option("--model <model>", "LLM model to use")
    .option("--cost-ceiling <usd>", "Hard per-review USD cost ceiling. Aborts cleanly with partial findings if exceeded.")
    .option("--tui", "Open the local terminal UI after the review completes", false)
    .option("--diff-base <ref>", "Git base ref to review against (for diff-aware review)")
    .option("--changed-only", "Restrict semgrep + prioritization to changed files", false)
    .option("--verbose", "Show detailed output", false)
    .option("--timeout <ms>", "AI agent timeout in milliseconds", "600000")
    .action(async (repo: string, opts: Record<string, string | boolean>) => {
      let costCeilingUsd: number | undefined;
      const ceilingSource =
        (opts.costCeiling as string | undefined) ?? process.env.PWNKIT_COST_CEILING_USD;
      if (ceilingSource !== undefined && ceilingSource !== "") {
        const parsed = Number(ceilingSource);
        if (!Number.isFinite(parsed) || parsed <= 0) {
          throw new Error(`Invalid cost ceiling '${ceilingSource}': must be a positive number (USD).`);
        }
        costCeilingUsd = parsed;
      }
      await runUnified({
        target: repo,
        targetType: "source-code",
        diffBase: opts.diffBase as string | undefined,
        changedOnly: opts.changedOnly as boolean,
        depth: (opts.depth as ScanDepth) ?? "default",
        format: (opts.format === "md" ? "markdown" : opts.format) as OutputFormat,
        runtime: (opts.runtime as RuntimeMode) ?? "auto",
        timeout: parseInt(opts.timeout as string, 10),
        verbose: opts.verbose as boolean,
        dbPath: opts.dbPath as string | undefined,
        apiKey: opts.apiKey as string | undefined,
        model: opts.model as string | undefined,
        costCeilingUsd,
        tui: opts.tui as boolean,
      });
    });
}
