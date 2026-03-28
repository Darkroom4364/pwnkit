import type { Command } from "commander";
import chalk from "chalk";
import { renderReplay } from "../formatters/replay.js";

export function registerReplayCommand(program: Command): void {
  program
    .command("replay")
    .description("Replay the last scan's attack chain as an animated terminal sequence")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--scan <scanId>", "Replay a specific scan by ID (default: last scan)")
    .action(async (opts) => {
      try {
        const { pwnkitDB } = await import("@pwnkit/db");
        const db = new pwnkitDB(opts.dbPath);

        let scanRecord;
        if (opts.scan) {
          scanRecord = db.getScan(opts.scan);
          if (!scanRecord) {
            // Try prefix match
            const all = db.listScans(100);
            scanRecord = all.find((s: { id: string }) => s.id.startsWith(opts.scan));
          }
          if (!scanRecord) {
            console.error(chalk.red(`Scan '${opts.scan}' not found.`));
            db.close();
            process.exit(2);
          }
        } else {
          const scans = db.listScans(1);
          if (scans.length === 0) {
            console.error(chalk.red("No scan history found. Run a scan first."));
            db.close();
            process.exit(2);
          }
          scanRecord = scans[0];
        }

        const dbFindings = db.getFindings(scanRecord.id);
        const target = db.getTarget(scanRecord.target);
        db.close();

        const summary = scanRecord.summary ? JSON.parse(scanRecord.summary) : {
          totalAttacks: 0, totalFindings: 0,
          critical: 0, high: 0, medium: 0, low: 0, info: 0,
        };

        const findings = dbFindings.map((f) => ({
          id: f.id,
          templateId: f.templateId,
          title: f.title,
          description: f.description,
          severity: f.severity as import("@pwnkit/shared").Severity,
          category: f.category as import("@pwnkit/shared").AttackCategory,
          status: f.status as import("@pwnkit/shared").FindingStatus,
          evidence: {
            request: f.evidenceRequest,
            response: f.evidenceResponse,
            analysis: f.evidenceAnalysis ?? undefined,
          },
          timestamp: f.timestamp,
        }));

        const targetInfo = target
          ? {
              url: target.url,
              type: target.type as import("@pwnkit/shared").TargetInfo["type"],
              systemPrompt: target.systemPrompt ?? undefined,
              detectedFeatures: target.detectedFeatures
                ? JSON.parse(target.detectedFeatures)
                : undefined,
              endpoints: target.endpoints ? JSON.parse(target.endpoints) : undefined,
            }
          : undefined;

        await renderReplay({
          target: scanRecord.target,
          targetInfo,
          findings,
          summary,
          durationMs: scanRecord.durationMs ?? 0,
        });
      } catch (err) {
        console.error(
          chalk.red("Failed to replay: " + (err instanceof Error ? err.message : String(err)))
        );
        process.exit(2);
      }
    });
}
