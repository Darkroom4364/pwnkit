import type { Command } from "commander";
import chalk from "chalk";

type FindingsListOptions = {
  dbPath?: string;
  scan?: string;
  severity?: string;
  category?: string;
  status?: string;
  limit?: string;
};

function withFindingsListOptions(command: Command): Command {
  return command
    .option("--db-path <path>", "Path to SQLite database")
    .option("--scan <scanId>", "Filter by scan ID")
    .option("--severity <severity>", "Filter by severity: critical, high, medium, low, info")
    .option("--category <category>", "Filter by attack category")
    .option("--status <status>", "Filter by status: discovered, verified, confirmed, scored, reported, false-positive")
    .option("--limit <n>", "Max findings to show", "50");
}

async function renderFindingsList(opts: FindingsListOptions): Promise<void> {
  const { pwnkitDB } = await import("@pwnkit/db");
  const db = new pwnkitDB(opts.dbPath);
  const rows = db.listFindings({
    scanId: opts.scan,
    severity: opts.severity,
    category: opts.category,
    status: opts.status,
    limit: parseInt(opts.limit ?? "50", 10),
  });
  db.close();

  if (rows.length === 0) {
    console.log(chalk.gray("No findings found."));
    return;
  }

  console.log("");
  console.log(chalk.red.bold("  \u25C6 pwnkit") + chalk.gray(` findings (${rows.length})`));
  console.log("");

  for (const f of rows) {
    const sevColor =
      f.severity === "critical" ? chalk.red.bold :
      f.severity === "high" ? chalk.redBright :
      f.severity === "medium" ? chalk.yellow :
      f.severity === "low" ? chalk.blue :
      chalk.gray;

    const statusColor =
      f.status === "reported" ? chalk.green :
      f.status === "scored" ? chalk.cyan :
      f.status === "verified" ? chalk.yellow :
      f.status === "false-positive" ? chalk.strikethrough.gray :
      chalk.white;

    console.log(
      `  ${sevColor(f.severity.padEnd(8))} ${statusColor(f.status.padEnd(14))} ${chalk.white(f.title)}`
    );
    console.log(
      `  ${chalk.gray(f.id.slice(0, 8))}  ${chalk.gray(f.category)}  ${chalk.gray(`scan:${f.scanId.slice(0, 8)}`)}`
    );
    console.log("");
  }
}

export function registerFindingsCommand(program: Command): void {
  const findingsCmd = withFindingsListOptions(
    program
      .command("findings")
      .description("Browse and manage persisted findings")
  ).action(async (opts: FindingsListOptions) => {
    await renderFindingsList(opts);
  });

  withFindingsListOptions(
    findingsCmd
      .command("list")
      .description("List findings from the database")
  ).action(async (opts: FindingsListOptions) => {
    await renderFindingsList(opts);
  });

  findingsCmd
    .command("show")
    .description("Show detailed information about a finding")
    .argument("<id>", "Finding ID (full or prefix)")
    .option("--db-path <path>", "Path to SQLite database")
    .action(async (id: string, opts) => {
      const { pwnkitDB } = await import("@pwnkit/db");
      const db = new pwnkitDB(opts.dbPath);

      // Support prefix matching
      let finding = db.getFinding(id);
      if (!finding) {
        const all = db.listFindings({ limit: 1000 });
        finding = all.find((f: { id: string }) => f.id.startsWith(id));
      }
      db.close();

      if (!finding) {
        console.error(chalk.red(`Finding '${id}' not found.`));
        process.exit(1);
      }

      console.log("");
      console.log(chalk.red.bold("  \u25C6 pwnkit") + chalk.gray(" finding detail"));
      console.log("");

      const sevColor =
        finding.severity === "critical" ? chalk.red.bold :
        finding.severity === "high" ? chalk.redBright :
        finding.severity === "medium" ? chalk.yellow :
        finding.severity === "low" ? chalk.blue :
        chalk.gray;

      console.log(`  ${chalk.white.bold(finding.title)}`);
      console.log(`  ${sevColor(finding.severity.toUpperCase())} ${chalk.gray("\u2502")} ${chalk.white(finding.status)} ${chalk.gray("\u2502")} ${chalk.gray(finding.category)}`);
      if (finding.score != null) {
        console.log(`  ${chalk.gray("Score:")} ${chalk.cyan(String(finding.score) + "/100")}`);
      }
      console.log("");
      console.log(`  ${chalk.gray("ID:")}       ${finding.id}`);
      console.log(`  ${chalk.gray("Scan:")}     ${finding.scanId}`);
      console.log(`  ${chalk.gray("Template:")} ${finding.templateId}`);
      console.log(`  ${chalk.gray("Time:")}     ${new Date(finding.timestamp).toISOString()}`);
      console.log("");
      console.log(`  ${chalk.gray("Description:")}`);
      console.log(`  ${finding.description}`);
      console.log("");
      console.log(`  ${chalk.gray("Evidence \u2014 Request:")}`);
      console.log(`  ${chalk.dim(finding.evidenceRequest)}`);
      console.log("");
      console.log(`  ${chalk.gray("Evidence \u2014 Response:")}`);
      console.log(`  ${chalk.dim(finding.evidenceResponse)}`);
      if (finding.evidenceAnalysis) {
        console.log("");
        console.log(`  ${chalk.gray("Evidence \u2014 Analysis:")}`);
        console.log(`  ${chalk.dim(finding.evidenceAnalysis)}`);
      }
      console.log("");
    });
}
