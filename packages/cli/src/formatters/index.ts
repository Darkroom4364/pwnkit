import type { ScanReport, OutputFormat } from "@nightfang/shared";
import { formatTerminal } from "./terminal.js";
import { formatJson } from "./json.js";
import { formatMarkdown } from "./markdown.js";

export function formatReport(report: ScanReport, format: OutputFormat): string {
  switch (format) {
    case "terminal":
      return formatTerminal(report);
    case "json":
      return formatJson(report);
    case "markdown":
      return formatMarkdown(report);
  }
}
