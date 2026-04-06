import type { Command } from "commander";
import type { ScanDepth, OutputFormat, RuntimeMode } from "@pwnkit/shared";
import { runUnified } from "./run.js";

export function registerAuditCommand(program: Command): void {
  program
    .command("audit")
    .description("Audit an npm package for security vulnerabilities")
    .argument("<package>", "npm package name (e.g. lodash, express)")
    .option("--version <version>", "Specific version to audit (default: latest)")
    .option("--depth <depth>", "Audit depth: quick, default, deep", "default")
    .option("--format <format>", "Output format: terminal, json, md, html, sarif, pdf", "terminal")
    .option("--runtime <runtime>", "Runtime: auto, claude, codex, gemini, api", "auto")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--api-key <key>", "API key for LLM provider")
    .option("--model <model>", "LLM model to use")
    .option("--cost-ceiling <usd>", "Hard per-audit USD cost ceiling. Aborts cleanly with partial findings if exceeded.")
    .option("--verbose", "Show detailed output", false)
    .option("--timeout <ms>", "AI agent timeout in milliseconds", "600000")
    .action(async (packageName: string, opts: Record<string, string | boolean>) => {
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
        target: packageName,
        targetType: "npm-package",
        depth: (opts.depth as ScanDepth) ?? "default",
        format: (opts.format === "md" ? "markdown" : opts.format) as OutputFormat,
        runtime: (opts.runtime as RuntimeMode) ?? "auto",
        timeout: parseInt(opts.timeout as string, 10),
        verbose: opts.verbose as boolean,
        dbPath: opts.dbPath as string | undefined,
        apiKey: opts.apiKey as string | undefined,
        model: opts.model as string | undefined,
        packageVersion: opts.version as string | undefined,
        costCeilingUsd,
      });
    });
}
