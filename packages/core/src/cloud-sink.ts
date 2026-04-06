/**
 * Optional webhook sink for streaming findings and final reports to a remote
 * HTTP endpoint in real time.
 *
 * This module is a no-op unless the user opts in via environment variables:
 *
 *   PWNKIT_CLOUD_SINK     — base URL of the remote API (e.g. https://api.example.com)
 *   PWNKIT_CLOUD_SCAN_ID  — scan correlation id (sent in X-Pwnkit-Scan-Id header
 *                           AND used in the URL path)
 *   PWNKIT_CLOUD_TOKEN    — bearer token (sent as Authorization header)
 *
 * When PWNKIT_CLOUD_SINK is unset, behavior is identical to today's local-only
 * runs. When set, every saved finding and the final scan report are POSTed to:
 *
 *   ${PWNKIT_CLOUD_SINK}/scans/${PWNKIT_CLOUD_SCAN_ID}/findings
 *
 * The integration is intentionally fire-and-forget: any error returned by the
 * remote endpoint is logged to stderr but does NOT abort the scan. Local
 * output is unchanged either way.
 *
 * The behavior can be force-disabled with PWNKIT_FEATURE_CLOUD_SINK=0 even when
 * the URL env var is set, mirroring the existing feature-flag pattern in
 * `agent/features.ts`.
 */
import { features } from "./agent/features.js";

export interface CloudSinkConfig {
  /** Base URL of the remote sink, e.g. https://api.example.com */
  sinkUrl: string;
  /** Scan correlation id used in the URL path AND the X-Pwnkit-Scan-Id header */
  scanId: string;
  /** Optional bearer token sent as Authorization header */
  token?: string;
}

/**
 * Read sink configuration from the environment. Returns null when the feature
 * flag is disabled or when PWNKIT_CLOUD_SINK is unset (the no-op case).
 */
export function getCloudSinkConfig(): CloudSinkConfig | null {
  if (!features.cloudSink) return null;

  const sinkUrl = process.env.PWNKIT_CLOUD_SINK?.trim();
  if (!sinkUrl) return null;

  const scanId = process.env.PWNKIT_CLOUD_SCAN_ID?.trim();
  if (!scanId) return null;

  const token = process.env.PWNKIT_CLOUD_TOKEN?.trim() || undefined;
  return { sinkUrl, scanId, token };
}

function buildHeaders(config: CloudSinkConfig): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Pwnkit-Scan-Id": config.scanId,
  };
  if (config.token) headers["Authorization"] = `Bearer ${config.token}`;
  return headers;
}

async function postJson(
  url: string,
  body: unknown,
  config: CloudSinkConfig,
  kind: string,
): Promise<void> {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: buildHeaders(config),
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      // Drain body for diagnostics, then continue. Sink failures must never
      // abort the scan.
      const text = await res.text().catch(() => "");
      process.stderr.write(
        `[pwnkit cloud-sink] ${kind} POST ${url} returned ${res.status}: ${text.slice(0, 200)}\n`,
      );
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`[pwnkit cloud-sink] ${kind} POST ${url} failed: ${msg}\n`);
  }
}

/**
 * POST a single finding to the remote sink. No-op if env vars unset.
 */
export async function postFinding(
  finding: unknown,
  config: CloudSinkConfig | null = getCloudSinkConfig(),
): Promise<void> {
  if (!config) return;
  const url = `${config.sinkUrl.replace(/\/+$/, "")}/scans/${encodeURIComponent(config.scanId)}/findings`;
  await postJson(url, { finding }, config, "finding");
}

/**
 * POST the final scan/audit report (with usage + cost) to the remote sink.
 * No-op if env vars unset.
 */
export async function postFinalReport(
  report: unknown,
  config: CloudSinkConfig | null = getCloudSinkConfig(),
): Promise<void> {
  if (!config) return;
  const url = `${config.sinkUrl.replace(/\/+$/, "")}/scans/${encodeURIComponent(config.scanId)}/findings`;
  await postJson(url, { report, final: true }, config, "report");
}
