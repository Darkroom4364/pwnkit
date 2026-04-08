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

type Pane = "scans" | "findings" | "details";
type InputMode = "normal" | "filter";

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

function nextPane(current: Pane): Pane {
  if (current === "scans") return "findings";
  if (current === "findings") return "details";
  return "scans";
}

function previousPane(current: Pane): Pane {
  if (current === "details") return "findings";
  if (current === "findings") return "scans";
  return "details";
}

function Stat({
  label,
  value,
  color = "#FFFFFF",
}: {
  label: string;
  value: string;
  color?: string;
}) {
  return (
    <Box marginRight={3}>
      <Text color="#6B7280">{label}: </Text>
      <Text color={color} bold>{value}</Text>
    </Box>
  );
}

function OperatorTui({ dbPath, refreshMs = 4000 }: TuiOptions): React.ReactElement {
  const { exit } = useApp();
  const [pane, setPane] = useState<Pane>("scans");
  const [mode, setMode] = useState<InputMode>("normal");
  const [filter, setFilter] = useState("");
  const [scanIndex, setScanIndex] = useState(0);
  const [findingIndex, setFindingIndex] = useState(0);
  const [detailOffset, setDetailOffset] = useState(0);
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

  const scans = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return state.scans;
    return state.scans.filter((scan) =>
      [
        scan.target,
        scan.depth,
        scan.runtime,
        scan.mode,
        scan.status,
        scan.id,
      ]
        .join(" ")
        .toLowerCase()
        .includes(q),
    );
  }, [filter, state.scans]);
  const selectedScan = scans[scanIndex] ?? null;
  const findingsForScan = useMemo(() => {
    if (!selectedScan) return [] as FindingRow[];
    const source = state.findings.filter((finding) => finding.scanId === selectedScan.id);
    const q = filter.trim().toLowerCase();
    if (!q) return source;
    return source.filter((finding) =>
      [
        finding.title,
        finding.category,
        finding.severity,
        finding.status,
        finding.triageStatus ?? "",
        finding.triageNote ?? "",
      ]
        .join(" ")
        .toLowerCase()
        .includes(q),
    );
  }, [filter, selectedScan, state.findings]);
  const selectedFinding = findingsForScan[findingIndex] ?? null;
  const eventsForSelection = useMemo(() => {
    if (!selectedScan) return [] as EventRow[];
    const source = state.events.filter((event) => event.scanId === selectedScan.id);
    if (!selectedFinding) return source.slice(0, 8);
    return source
      .filter((event) => !event.findingId || event.findingId === selectedFinding.id)
      .slice(0, 8);
  }, [selectedScan, selectedFinding, state.events]);

  const detailLines = useMemo(() => {
    const lines: Array<{ color: string; text: string; bold?: boolean }> = [];

    if (selectedFinding) {
      lines.push({
        color: "#FFFFFF",
        text: selectedFinding.title,
        bold: true,
      });
      lines.push({
        color: severityColor(selectedFinding.severity),
        text: `${selectedFinding.severity.toUpperCase()} · ${selectedFinding.category}`,
      });
      if (selectedFinding.triageStatus || selectedFinding.triageNote) {
        lines.push({
          color: "#6B7280",
          text: `triage: ${selectedFinding.triageStatus ?? "new"}${selectedFinding.triageNote ? ` · ${selectedFinding.triageNote}` : ""}`,
        });
      }
      lines.push({ color: "#9CA3AF", text: selectedFinding.description });
      if (selectedFinding.evidenceRequest) {
        lines.push({ color: "#6B7280", text: "Request" });
        lines.push({ color: "#D1D5DB", text: selectedFinding.evidenceRequest });
      }
      if (selectedFinding.evidenceResponse) {
        lines.push({ color: "#6B7280", text: "Response" });
        lines.push({ color: "#D1D5DB", text: selectedFinding.evidenceResponse });
      }
      if (selectedFinding.evidenceAnalysis) {
        lines.push({ color: "#6B7280", text: "Analysis" });
        lines.push({ color: "#D1D5DB", text: selectedFinding.evidenceAnalysis });
      }
    } else if (selectedScan) {
      lines.push({
        color: "#FFFFFF",
        text: selectedScan.target,
        bold: true,
      });
      lines.push({
        color: "#9CA3AF",
        text: `${selectedScan.mode}/${selectedScan.depth} · ${selectedScan.runtime} · ${selectedScan.status}`,
      });
      lines.push({
        color: "#9CA3AF",
        text: `Started ${formatStarted(selectedScan.startedAt)}`,
      });
      if (selectedScan.completedAt) {
        lines.push({
          color: "#9CA3AF",
          text: `Completed ${formatStarted(selectedScan.completedAt)}`,
        });
      }
    }

    lines.push({ color: "#6B7280", text: "" });
    lines.push({ color: "#6B7280", text: "Recent events" });
    if (eventsForSelection.length === 0) {
      lines.push({ color: "#9CA3AF", text: "No recent events." });
    } else {
      for (const event of eventsForSelection) {
        lines.push({
          color: "#FFFFFF",
          text: `${event.stage} · ${event.eventType}`,
        });
        lines.push({
          color: "#6B7280",
          text: event.payload,
        });
      }
    }

    return lines.flatMap((line) => {
      const source = line.text.length === 0 ? [""] : line.text.split(/\n/);
      return source.map((text) => ({ ...line, text }));
    });
  }, [eventsForSelection, selectedFinding, selectedScan]);

  const detailPageSize = 18;
  const maxDetailOffset = Math.max(0, detailLines.length - detailPageSize);
  const visibleDetailLines = detailLines.slice(detailOffset, detailOffset + detailPageSize);

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

  useEffect(() => {
    setDetailOffset(0);
  }, [selectedScan?.id, selectedFinding?.id]);

  useInput((input, key) => {
    if (mode === "filter") {
      if (key.escape) {
        setMode("normal");
        setFilter("");
        return;
      }
      if (key.return) {
        setMode("normal");
        return;
      }
      if (key.backspace || key.delete) {
        setFilter((current) => current.slice(0, -1));
        return;
      }
      if (input && !key.ctrl && !key.meta) {
        setFilter((current) => current + input);
      }
      return;
    }

    if (key.escape || input === "q" || (key.ctrl && input === "c")) {
      exit();
      return;
    }

    if (input === "/") {
      setMode("filter");
      setFilter("");
      return;
    }

    if (input === "\t" || key.rightArrow) {
      setPane((current) => nextPane(current));
      return;
    }

    if (key.leftArrow) {
      setPane((current) => previousPane(current));
      return;
    }

    if (key.upArrow) {
      if (pane === "scans") {
        setScanIndex((current) => Math.max(0, current - 1));
        setFindingIndex(0);
      } else if (pane === "findings") {
        setFindingIndex((current) => Math.max(0, current - 1));
      } else {
        setDetailOffset((current) => Math.max(0, current - 1));
      }
      return;
    }

    if (key.downArrow) {
      if (pane === "scans") {
        setScanIndex((current) => Math.min(scans.length - 1, current + 1));
        setFindingIndex(0);
      } else if (pane === "findings") {
        setFindingIndex((current) =>
          Math.min(findingsForScan.length - 1, current + 1),
        );
      } else {
        setDetailOffset((current) => Math.min(maxDetailOffset, current + 1));
      }
      return;
    }

    if (pane === "details") {
      if (input === "j") {
        setDetailOffset((current) => Math.min(maxDetailOffset, current + 1));
        return;
      }
      if (input === "k") {
        setDetailOffset((current) => Math.max(0, current - 1));
        return;
      }
      if (input === "d" || key.pageDown) {
        setDetailOffset((current) => Math.min(maxDetailOffset, current + detailPageSize));
        return;
      }
      if (input === "u" || key.pageUp) {
        setDetailOffset((current) => Math.max(0, current - detailPageSize));
        return;
      }
      if (input === "g") {
        setDetailOffset(0);
        return;
      }
      if (input === "G") {
        setDetailOffset(maxDetailOffset);
        return;
      }
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
      <Box marginBottom={1} flexDirection="row">
        <Stat label="runs" value={String(scans.length)} />
        <Stat label="findings" value={String(state.findings.length)} />
        <Stat
          label="critical"
          value={String(state.findings.filter((finding) => finding.severity === "critical").length)}
          color="#DC2626"
        />
        <Stat
          label="high"
          value={String(state.findings.filter((finding) => finding.severity === "high").length)}
          color="#EAB308"
        />
        <Stat label="pane" value={pane} color="#06B6D4" />
        <Stat label="refresh" value={`${refreshMs}ms`} color="#9CA3AF" />
      </Box>
      <Text color="#9CA3AF">
        {"  "}tab/←/→ switch pane · ↑/↓ navigate · / filter · r refresh · q quit
      </Text>
      {mode === "filter" ? (
        <Box>
          <Text color="#6B7280">  filter: </Text>
          <Text color="#FFFFFF">{filter}</Text>
          <Text color="#DC2626">█</Text>
        </Box>
      ) : filter ? (
        <Text color="#6B7280">  filter active: {filter}</Text>
      ) : null}
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
              active={pane === "details"}
              meta={`${detailOffset + 1}-${Math.min(detailOffset + detailPageSize, detailLines.length)}/${detailLines.length || 0}`}
            />
            <Box flexDirection="column" marginTop={1}>
              {visibleDetailLines.map((line, index) => (
                <Text
                  key={`${detailOffset}-${index}-${line.text.slice(0, 16)}`}
                  color={line.color}
                  bold={line.bold}
                  wrap="truncate-end"
                >
                  {truncate(line.text, 300)}
                </Text>
              ))}
            </Box>
          </Box>
        </Box>
      ) : null}
      {!loading && !error && scans.length > 0 ? (
        <Box marginTop={1}>
          <Text color="#6B7280">
            {"  "}
            {pane === "scans"
              ? `runs ${scanIndex + 1}/${Math.max(scans.length, 1)} · ${selectedScan?.id.slice(0, 8) ?? "none"}`
              : pane === "findings"
                ? `findings ${findingIndex + 1}/${Math.max(findingsForScan.length, 1)} · ${selectedFinding?.id.slice(0, 8) ?? "none"}`
                : `details ${detailOffset + 1}-${Math.min(detailOffset + detailPageSize, detailLines.length)}/${detailLines.length || 0}`}
            {selectedScan ? ` · ${selectedScan.mode}/${selectedScan.depth} · ${selectedScan.runtime}` : ""}
            {selectedFinding ? ` · ${selectedFinding.severity}/${selectedFinding.category}` : ""}
            {filter ? ` · filter:${filter}` : ""}
          </Text>
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
