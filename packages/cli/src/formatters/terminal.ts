import chalk from "chalk";
import type { ScanReport, Finding, Severity } from "@nightfang/shared";

const SEVERITY_COLORS: Record<Severity, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.blue,
  info: chalk.gray,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: "!!!",
  high: " !! ",
  medium: " ! ",
  low: " - ",
  info: " . ",
};

export function formatTerminal(report: ScanReport): string {
  const lines: string[] = [];

  lines.push("");
  lines.push(chalk.bold.white("  NIGHTFANG SCAN REPORT"));
  lines.push(chalk.gray("  " + "=".repeat(50)));
  lines.push("");
  lines.push(`  ${chalk.gray("Target:")}  ${report.target}`);
  lines.push(`  ${chalk.gray("Depth:")}   ${report.scanDepth}`);
  lines.push(`  ${chalk.gray("Duration:")} ${formatDuration(report.durationMs)}`);
  lines.push("");

  // Summary bar
  const { summary } = report;
  lines.push(chalk.bold("  Summary"));
  lines.push(
    `  ${chalk.gray("Attacks:")} ${summary.totalAttacks}  ${chalk.gray("Findings:")} ${summary.totalFindings}`
  );

  if (summary.totalFindings > 0) {
    const parts: string[] = [];
    if (summary.critical > 0)
      parts.push(SEVERITY_COLORS.critical(` ${summary.critical} CRITICAL `));
    if (summary.high > 0) parts.push(SEVERITY_COLORS.high(`${summary.high} HIGH`));
    if (summary.medium > 0)
      parts.push(SEVERITY_COLORS.medium(`${summary.medium} MEDIUM`));
    if (summary.low > 0) parts.push(SEVERITY_COLORS.low(`${summary.low} LOW`));
    if (summary.info > 0) parts.push(SEVERITY_COLORS.info(`${summary.info} INFO`));
    lines.push(`  ${parts.join("  ")}`);
  }

  lines.push("");

  // Findings
  if (report.findings.length === 0) {
    lines.push(chalk.green("  No vulnerabilities found."));
  } else {
    lines.push(chalk.bold("  Findings"));
    lines.push(chalk.gray("  " + "-".repeat(50)));

    for (const finding of report.findings) {
      lines.push(formatFinding(finding));
    }
  }

  lines.push("");
  return lines.join("\n");
}

function formatFinding(finding: Finding): string {
  const lines: string[] = [];
  const color = SEVERITY_COLORS[finding.severity];
  const icon = SEVERITY_ICONS[finding.severity];

  lines.push(`  ${color(`[${icon}]`)} ${chalk.bold(finding.title)}`);
  lines.push(`      ${chalk.gray("Category:")} ${finding.category}`);
  lines.push(`      ${chalk.gray("Status:")}   ${finding.status}`);
  lines.push(`      ${chalk.gray(finding.description)}`);

  if (finding.evidence.analysis) {
    lines.push(`      ${chalk.gray("Evidence:")} ${finding.evidence.analysis}`);
  }

  lines.push("");
  return lines.join("\n");
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}
