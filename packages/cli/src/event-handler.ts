import chalk from "chalk";
import type { OutputFormat } from "@pwnkit/shared";
import type { createpwnkitSpinner } from "./spinner.js";
import { renderProgressBar } from "./formatters/terminal.js";

export interface EventHandlerOptions {
  format: OutputFormat;
  spinner: ReturnType<typeof createpwnkitSpinner> | null;
  /** Enable attack:end progress tracking (used by scan command). */
  trackAttacks?: {
    getTotal: () => number;
    getDone: () => number;
    incrementDone: () => void;
  };
}

export function createEventHandler(opts: EventHandlerOptions) {
  const { format, spinner, trackAttacks } = opts;

  return (event: { type: string; stage?: string; message: string; data?: unknown }) => {
    if (format !== "terminal") return;

    switch (event.type) {
      case "stage:start": {
        const msg = event.message;
        if (msg.startsWith("Reading ")) {
          spinner?.stop();
          console.log(`    ${chalk.cyan("\u2192")} ${chalk.cyan("read")} ${chalk.gray(msg.replace("Reading ", ""))}`);
          spinner?.start();
        } else if (msg.startsWith("Running: ")) {
          spinner?.stop();
          console.log(`    ${chalk.magenta("\u2192")} ${chalk.magenta("exec")} ${chalk.gray(msg.replace("Running: ", ""))}`);
          spinner?.start();
        } else {
          spinner?.update(msg);
          spinner?.start();
        }
        break;
      }

      case "attack:end":
        if (trackAttacks) {
          trackAttacks.incrementDone();
          const total = trackAttacks.getTotal();
          if (spinner && total > 0) {
            spinner.update(`Running attacks ${renderProgressBar(trackAttacks.getDone(), total)}`);
          }
        }
        break;

      case "stage:end":
        if (trackAttacks && event.stage === "attack") {
          const total = trackAttacks.getTotal();
          spinner?.succeed(
            `${chalk.gray("Attacks complete")} ${renderProgressBar(total, total)}`
          );
        } else if (
          event.stage === "discovery" &&
          typeof event.data === "object" &&
          event.data !== null &&
          "success" in event.data &&
          event.data.success === false
        ) {
          spinner?.warn(event.message);
        } else {
          spinner?.succeed(event.message);
        }
        break;

      case "finding":
        spinner?.stop();
        console.log(
          `    ${chalk.yellow("\u26A1")} ${chalk.yellow(event.message)}`
        );
        spinner?.start();
        break;

      case "error":
        spinner?.fail(event.message);
        break;
    }
  };
}
