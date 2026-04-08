import type { Command } from "commander";

type TuiOptions = {
  dbPath?: string;
  refreshMs?: string;
};

export function registerTuiCommand(program: Command): void {
  program
    .command("tui")
    .alias("watch")
    .description("Open a local read-only terminal UI for runs, findings, and evidence")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--refresh-ms <n>", "Refresh interval in milliseconds", "4000")
    .action(async (opts: TuiOptions) => {
      const { showOperatorTui } = await import("../ui/Tui.js");
      await showOperatorTui({
        dbPath: opts.dbPath,
        refreshMs: Number.parseInt(opts.refreshMs ?? "4000", 10),
      });
    });
}
