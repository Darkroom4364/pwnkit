import type { ScanReport } from "@nightfang/shared";

export function formatJson(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}
