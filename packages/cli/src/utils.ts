import { gzipSync } from "zlib";
import type { ScanReport, AuditReport, ReviewReport, ScanDepth } from "@pwnkit/shared";

/**
 * Encode a report as a base64url-encoded gzipped JSON string for use in a share URL.
 */
export function buildShareUrl(report: ScanReport | AuditReport | ReviewReport): string {
  const json = JSON.stringify(report);
  const compressed = gzipSync(Buffer.from(json, "utf-8"));
  const b64 = compressed.toString("base64url");
  return `https://pwnkit.com/r#${b64}`;
}

export function depthLabel(depth: ScanDepth): string {
  switch (depth) {
    case "quick":
      return "~5 probes";
    case "default":
      return "~50 probes";
    case "deep":
      return "full coverage";
  }
}
