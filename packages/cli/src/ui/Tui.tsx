import React, { useEffect, useMemo, useState } from "react";
import { Box, Text, useApp, useInput, render } from "ink";
import type { FindingTriageStatus } from "@pwnkit/shared";
import { printBanner } from "./banner.js";

type TuiOptions = {
  dbPath?: string;
  refreshMs?: number;
};

type ScanRow = {
  id: string;
  target: string;
  depth: string;
  runtime: string;
  mode: string;
  status: string;
  startedAt: string;
  completedAt?: string | null;
  durationMs?: number | null;
  summary?: string | null;
};

type FindingRow = {
  id: string;
  scanId: string;
  title: string;
  description: string;
  severity: string;
  category: string;
  status: string;
  fingerprint?: string | null;
  triageStatus?: string | null;
  triageNote?: string | null;
  timestamp: number;
  evidenceRequest: string;
  evidenceResponse: string;
  evidenceAnalysis?: string | null;
};

type EventRow = {
  id: string;
  scanId: string;
  stage: string;
  eventType: string;
  findingId?: string | null;
  agentRole?: string | null;
  payload: string;
  timestamp: number;
};

type Pane = "scans" | "findings";

function parseSummary(summary?: string | null): Record<string, number> {
  if (!summary) return {};
  try {
    return JSON.parse(summary) as Record<string, number>;
  } catch {
    return {};
  }
}

function formatDuration(ms?: number | null): string {
  if (!ms || ms <= 0) return "-";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatStarted(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return `${date.toLocaleDateString()} ${date.toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  })}`;
}

function severityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
    case "high":
      return "#DC2626";
    case "medium":
      return "#EAB308";
    case "low":
      return "#06B6D4";
    default:
      return "#6B7280";
  }
}

function statusColor(status: string): string {
  if (status === "completed" || status === "reported") return "#22C55E";
  if (status === "failed" || status === "false-positive") return "#DC2626";
  if (status === "running" || status === "verified") return "#EAB308";
  return "#9CA3AF";
}

function triageColor(status?: string | null): string {
  switch ((status ?? "new") as FindingTriageStatus | "new") {
    case "accepted":
      return "#22C55E";
    case "suppressed":
      return "#6B7280";
    default:
      return "#06B6D4";
  }
}

function truncate(value: string | undefined | null, max = 120): string {
  if (!value) return "";
  const compact = value.replace(/\s+/g, " ").trim();
  if (compact.length <= max) return compact;
  return `${compact.slice(0, max - 1)}…`;
}

async function loadState(dbPath?: string): Promise<{
  scans: ScanRow[];
  findings: FindingRow[];
  events: EventRow[];
}> {
  const { pwnkitDB } = await import("@pwnkit/db");
  const db = new pwnkitDB(dbPath);
  try {
    return {
      scans: db.listScans(50) as ScanRow[],
      findings: db.listFindings({ limit: 500 }) as FindingRow[],
      events: db.listRecentEvents(100) as EventRow[],
    };
  } finally {
    db.close();
  }
}

function PaneTitle({
  label,
  active,
  meta,
}: {
  label: string;
  active: boolean;
  meta?: string;
}) {
  return (
    <Box justifyContent="space-between">
      <Text color={active ? "#DC2626" : "#9CA3AF"} bold={active}>
        {label}
      </Text>
      {meta ? <Text color="#6B7280">{meta}</Text> : null}
    </Box>
  );
}

function OperatorTui({ dbPath, refreshMs = 4000 }: TuiOptions): React.ReactElement {
  const { exit } = useApp();
  const [pane, setPane] = useState<Pane>("scans");
  const [scanIndex, setScanIndex] = useState(0);
  const [findingIndex, setFindingIndex] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [state, setState] = useState<{
    scans: ScanRow[];
    findings: FindingRow[];
    events: EventRow[];
  }>({ scans: [], findings: [], events: [] });

  useEffect(() => {
    let alive = true;

    const refresh = async () => {
      try {
        const next = await loadState(dbPath);
        if (!alive) return;
        setState(next);
        setError(null);
      } catch (err) {
        if (!alive) return;
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        if (alive) setLoading(false);
      }
    };

    void refresh();
    const timer = setInterval(() => void refresh(), refreshMs);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [dbPath, refreshMs]);

  const scans = state.scans;
  const selectedScan = scans[scanIndex] ?? null;
  const findingsForScan = useMemo(() => {
    if (!selectedScan) return [] as FindingRow[];
    return state.findings.filter((finding) => finding.scanId === selectedScan.id);
  }, [selectedScan, state.findings]);
  const selectedFinding = findingsForScan[findingIndex] ?? null;
  const eventsForSelection = useMemo(() => {
    if (!selectedScan) return [] as EventRow[];
    const source = state.events.filter((event) => event.scanId === selectedScan.id);
    if (!selectedFinding) return source.slice(0, 8);
    return source
      .filter((event) => !event.findingId || event.findingId === selectedFinding.id)
      .slice(0, 8);
  }, [selectedScan, selectedFinding, state.events]);

  useEffect(() => {
    if (scanIndex >= scans.length) {
      setScanIndex(Math.max(0, scans.length - 1));
    }
  }, [scanIndex, scans.length]);

  useEffect(() => {
    if (findingIndex >= findingsForScan.length) {
      setFindingIndex(Math.max(0, findingsForScan.length - 1));
    }
  }, [findingIndex, findingsForScan.length]);

  useInput((input, key) => {
    if (key.escape || input === "q" || (key.ctrl && input === "c")) {
      exit();
      return;
    }

    if (input === "\t" || key.rightArrow) {
      setPane((current) => (current === "scans" ? "findings" : "scans"));
      return;
    }

    if (key.leftArrow) {
      setPane((current) => (current === "findings" ? "scans" : "findings"));
      return;
    }

    if (key.upArrow) {
      if (pane === "scans") {
        setScanIndex((current) => Math.max(0, current - 1));
        setFindingIndex(0);
      } else {
        setFindingIndex((current) => Math.max(0, current - 1));
      }
      return;
    }

    if (key.downArrow) {
      if (pane === "scans") {
        setScanIndex((current) => Math.min(scans.length - 1, current + 1));
        setFindingIndex(0);
      } else {
        setFindingIndex((current) =>
          Math.min(findingsForScan.length - 1, current + 1),
        );
      }
      return;
    }

    if (input === "r") {
      setLoading(true);
      void loadState(dbPath)
        .then((next) => {
          setState(next);
          setError(null);
        })
        .catch((err) => setError(err instanceof Error ? err.message : String(err)))
        .finally(() => setLoading(false));
    }
  });

  return (
    <Box flexDirection="column" paddingLeft={1}>
      <Text color="#9CA3AF">
        {"  "}tab/←/→ switch pane · ↑/↓ navigate · r refresh · q quit
      </Text>
      <Text> </Text>
      {loading ? <Text color="#9CA3AF">  Loading local pwnkit state…</Text> : null}
      {error ? <Text color="#DC2626">  {error}</Text> : null}
      {!loading && !error && scans.length === 0 ? (
        <Text color="#9CA3AF">  No local scans found. Run a scan, audit, or review first.</Text>
      ) : null}

      {!loading && !error && scans.length > 0 ? (
        <Box flexDirection="row" gap={2}>
          <Box
            flexDirection="column"
            width={40}
            borderStyle="round"
            borderColor={pane === "scans" ? "#DC2626" : "#444"}
            paddingX={1}
            paddingY={0}
          >
            <PaneTitle
              label="Runs"
              active={pane === "scans"}
              meta={`${scans.length} total`}
            />
            <Box flexDirection="column" marginTop={1}>
              {scans.slice(0, 14).map((scan, index) => {
                const selected = index === scanIndex;
                const summary = parseSummary(scan.summary);
                return (
                  <Box key={scan.id} marginBottom={1}>
                    <Text color={selected ? "#DC2626" : "#6B7280"}>
                      {selected ? "❯ " : "  "}
                    </Text>
                    <Box flexDirection="column">
                      <Text color={selected ? "#FFFFFF" : "#D1D5DB"} bold={selected}>
                        {truncate(scan.target, 28)}
                      </Text>
                      <Text color="#6B7280">
                        {scan.mode}/{scan.depth} · {scan.runtime} ·{" "}
                        <Text color={statusColor(scan.status)}>{scan.status}</Text>
                      </Text>
                      <Text color="#6B7280">
                        {summary.totalFindings ?? 0} findings · {formatDuration(scan.durationMs)}
                      </Text>
                    </Box>
                  </Box>
                );
              })}
            </Box>
          </Box>

          <Box
            flexDirection="column"
            width={48}
            borderStyle="round"
            borderColor={pane === "findings" ? "#DC2626" : "#444"}
            paddingX={1}
            paddingY={0}
          >
            <PaneTitle
              label="Findings"
              active={pane === "findings"}
              meta={selectedScan ? `${findingsForScan.length} in run` : ""}
            />
            <Box flexDirection="column" marginTop={1}>
              {findingsForScan.length === 0 ? (
                <Text color="#9CA3AF">  No findings for this run.</Text>
              ) : (
                findingsForScan.slice(0, 14).map((finding, index) => {
                  const selected = index === findingIndex;
                  return (
                    <Box key={finding.id} marginBottom={1}>
                      <Text color={selected ? "#DC2626" : "#6B7280"}>
                        {selected ? "❯ " : "  "}
                      </Text>
                      <Box flexDirection="column">
                        <Text color={severityColor(finding.severity)} bold={selected}>
                          [{finding.severity}] {truncate(finding.title, 34)}
                        </Text>
                        <Text color="#6B7280">
                          {finding.category} ·{" "}
                          <Text color={triageColor(finding.triageStatus)}>
                            {finding.triageStatus ?? "new"}
                          </Text>
                        </Text>
                        {finding.triageNote ? (
                          <Text color="#6B7280">{truncate(finding.triageNote, 40)}</Text>
                        ) : null}
                      </Box>
                    </Box>
                  );
                })
              )}
            </Box>
          </Box>

          <Box
            flexDirection="column"
            flexGrow={1}
            borderStyle="round"
            borderColor="#444"
            paddingX={1}
            paddingY={0}
          >
            <PaneTitle
              label="Details"
              active={false}
              meta={selectedFinding ? selectedFinding.id.slice(0, 8) : selectedScan?.id.slice(0, 8)}
            />
            <Box flexDirection="column" marginTop={1}>
              {selectedFinding ? (
                <>
                  <Text bold color="#FFFFFF">
                    {selectedFinding.title}
                  </Text>
                  <Text color={severityColor(selectedFinding.severity)}>
                    {selectedFinding.severity.toUpperCase()} · {selectedFinding.category}
                  </Text>
                  <Text color="#9CA3AF">{truncate(selectedFinding.description, 260)}</Text>
                  {selectedFinding.evidenceRequest ? (
                    <>
                      <Text> </Text>
                      <Text color="#6B7280">Request</Text>
                      <Text color="#D1D5DB">{truncate(selectedFinding.evidenceRequest, 260)}</Text>
                    </>
                  ) : null}
                  {selectedFinding.evidenceAnalysis ? (
                    <>
                      <Text> </Text>
                      <Text color="#6B7280">Analysis</Text>
                      <Text color="#D1D5DB">{truncate(selectedFinding.evidenceAnalysis, 260)}</Text>
                    </>
                  ) : null}
                </>
              ) : selectedScan ? (
                <>
                  <Text bold color="#FFFFFF">
                    {selectedScan.target}
                  </Text>
                  <Text color="#9CA3AF">
                    {selectedScan.mode}/{selectedScan.depth} · {selectedScan.runtime}
                  </Text>
                  <Text color="#9CA3AF">
                    Started {formatStarted(selectedScan.startedAt)}
                  </Text>
                </>
              ) : null}

              <Text> </Text>
              <Text color="#6B7280">Recent events</Text>
              {eventsForSelection.length === 0 ? (
                <Text color="#9CA3AF">No recent events.</Text>
              ) : (
                eventsForSelection.map((event) => (
                  <Box key={event.id} flexDirection="column" marginBottom={1}>
                    <Text color="#FFFFFF">
                      {event.stage} · {event.eventType}
                    </Text>
                    <Text color="#6B7280">
                      {truncate(event.payload, 180)}
                    </Text>
                  </Box>
                ))
              )}
            </Box>
          </Box>
        </Box>
      ) : null}
    </Box>
  );
}

export async function showOperatorTui(options: TuiOptions): Promise<void> {
  printBanner();
  await new Promise<void>((resolve) => {
    const instance = render(<OperatorTui {...options} />);
    const done = () => {
      instance.unmount();
      resolve();
    };
    instance.waitUntilExit().then(done).catch(done);
  });
}
