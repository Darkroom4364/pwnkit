import React from "react";
import { Box, Text } from "ink";
import Spinner from "ink-spinner";
import {
  formatStageDetail,
  selectVisibleActions,
  truncateStageAction,
} from "@pwnkit/core";

// ── Types ──

export type StageStatusKind = "pending" | "running" | "done" | "error";

export interface StageFinding {
  severity: string;
  title: string;
}

export interface StageState {
  id: string;
  label: string;
  status: StageStatusKind;
  detail?: string;
  duration?: number;
  actions: string[];
  findings: StageFinding[];
  error?: string;
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info?: number;
  duration?: number;
  shareUrl?: string;
}

export interface ScanEvent {
  type: string;
  stage?: string;
  message: string;
  data?: unknown;
}

export interface ScanUIProps {
  stages: StageState[];
  summary: ScanSummary | null;
  thinking: string | null;
  exitHint?: string | null;
  /**
   * When false (the default), each stage shows only the last 3 actions and
   * each action is truncated to ~60 chars, to keep the banner terminal-friendly.
   * When true, more history is shown with a wider per-row budget so the user
   * can see what every turn is doing. Toggled at runtime via `v` or Ctrl+O in
   * the scan TUI. The actual caps live in @pwnkit/core's scan-ui-state module.
   */
  verbose?: boolean;
}

// ── Colors ──

const CRIMSON = "#DC2626";
const GREEN = "#22C55E";
const GRAY = "#6B7280";
const YELLOW = "#EAB308";
const CYAN = "#06B6D4";

function severityColor(s: string): string {
  switch (s.toLowerCase()) {
    case "critical": case "high": return CRIMSON;
    case "medium": return YELLOW;
    case "low": return CYAN;
    default: return GRAY;
  }
}

function formatDuration(ms: number): string {
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
}

// ── Stage Row ──

function StageRow({ stage, verbose }: { stage: StageState; verbose: boolean }) {
  const icon =
    stage.status === "done" ? (
      <Text color={GREEN}>{"✓"}</Text>
    ) : stage.status === "running" ? (
      <Text color={CRIMSON}><Spinner type="dots" /></Text>
    ) : stage.status === "error" ? (
      <Text color={CRIMSON}>{"✗"}</Text>
    ) : (
      <Text color={GRAY}>{"◌"}</Text>
    );

  // Compute verify confirmed count
  let verifyCount = "";
  if (stage.id === "verify" && stage.status === "done" && stage.actions.length > 0) {
    const confirmed = stage.actions.filter((a) => a.startsWith("\u2713")).length;
    const total = stage.actions.filter((a) => a.startsWith("\u2713") || a.startsWith("\u2717")).length;
    if (total > 0) {
      verifyCount = `${confirmed}/${total} confirmed`;
    }
  }

  return (
    <Box flexDirection="column">
      <Box gap={1}>
        <Text>{"  "}</Text>
        {icon}
        <Text bold color={stage.status === "pending" ? GRAY : undefined}>
          {stage.label.padEnd(12)}
        </Text>
        {verifyCount ? (
          <Text color={GREEN}>{verifyCount}</Text>
        ) : stage.detail ? (
          <Text
            color={stage.status === "done" ? GRAY : undefined}
            dimColor={stage.status === "done"}
          >
            {formatStageDetail(stage.detail, verbose)}
          </Text>
        ) : null}
        {stage.duration !== undefined && (
          <Text color={GRAY}> {formatDuration(stage.duration)}</Text>
        )}
      </Box>

      {/* Tool call actions — visible during and after execution */}
      {stage.actions.length > 0 && (() => {
        const { shown, hiddenCount } = selectVisibleActions(stage.actions, verbose);
        return (
          <Box flexDirection="column" marginLeft={6}>
            {hiddenCount > 0 && (
              <Text color={GRAY} dimColor>
                {`  … ${hiddenCount} earlier ${hiddenCount === 1 ? "action" : "actions"} hidden`}
              </Text>
            )}
            {shown.map((rawAction, i) => {
              const action = truncateStageAction(rawAction, verbose);
              // Verify stage: confirmed (✓) green+bold, rejected (✗) dim red+strikethrough
              if (stage.id === "verify") {
                const isConfirmed = action.startsWith("\u2713");
                const isRejected = action.startsWith("\u2717");
                if (isConfirmed) {
                  return (
                    <Text key={i} color={GREEN} bold>
                      {"→ "}{action}
                    </Text>
                  );
                }
                if (isRejected) {
                  return (
                    <Text key={i} color={CRIMSON} dimColor strikethrough>
                      {"→ "}{action}
                    </Text>
                  );
                }
                return (
                  <Text key={i} color={CYAN}>
                    {"→ "}{action}
                  </Text>
                );
              }
              return (
                <Text key={i} color={stage.status === "done" ? GRAY : CYAN} dimColor={stage.status === "done"}>
                  {"→ "}{action}
                </Text>
              );
            })}
          </Box>
        );
      })()}

      {/* Thinking text */}
      {stage.status === "running" && stage.actions.length === 0 && stage.detail && (
        <Box marginLeft={6}><Text color={GRAY} dimColor>{""}</Text></Box>
      )}

      {/* Findings */}
      {stage.findings.length > 0 && (
        <Box flexDirection="column" marginLeft={6}>
          {stage.findings.map((f, i) => (
            <Text key={i} color={severityColor(f.severity)}>
              {"⚡ "}<Text bold>[{f.severity}]</Text> {f.title}
            </Text>
          ))}
        </Box>
      )}
    </Box>
  );
}

// ── Summary ──

function SummaryBar({ summary }: { summary: ScanSummary }) {
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text color={GRAY}>{"  ──────────────────────────────────────"}</Text>
      <Box marginLeft={2} gap={2}>
        <Text color={summary.critical > 0 ? CRIMSON : GRAY} bold={summary.critical > 0}>
          {summary.critical} critical
        </Text>
        <Text color={summary.high > 0 ? CRIMSON : GRAY} bold={summary.high > 0}>
          {summary.high} high
        </Text>
        <Text color={summary.medium > 0 ? YELLOW : GRAY} bold={summary.medium > 0}>
          {summary.medium} medium
        </Text>
        <Text color={GRAY}>{summary.low} low</Text>
        <Text color={GRAY}>{summary.info ?? 0} info</Text>
      </Box>
      {summary.duration !== undefined && (
        <Box marginLeft={2}>
          <Text color={GRAY}>{formatDuration(summary.duration)}</Text>
        </Box>
      )}
      {summary.shareUrl && (
        <Box marginTop={1} marginLeft={2}>
          <Text color={GRAY}>Share: </Text>
          <Text color={CYAN}>{summary.shareUrl}</Text>
        </Box>
      )}
    </Box>
  );
}

// ── Outcome ──

/**
 * Per-stage terminal explanation rendered under the summary bar once the
 * scan finishes. This is where users finally get to read the full
 * "First attempt (10 turns): no findings. Retry (10 turns): Agent reached
 * max turns (10) without completing." sentence that the compact stage-row
 * detail clips at 55 chars. Without this block a 0-findings scan felt
 * like the agent "just stopped" — the narrative that explains *why* the
 * agent stopped is now always visible at the end.
 */
function OutcomeBlock({ stages }: { stages: StageState[] }) {
  const withDetail = stages.filter(
    (s) => s.status === "done" && s.detail && s.detail !== "done",
  );
  if (withDetail.length === 0) return null;
  return (
    <Box flexDirection="column" marginTop={1} marginLeft={2}>
      <Text color={GRAY} dimColor>Outcome:</Text>
      {withDetail.map((s) => (
        <Box key={s.id} marginLeft={2} flexDirection="column">
          <Box gap={1}>
            <Text color={GRAY} bold>{s.label}:</Text>
          </Box>
          <Box marginLeft={2}>
            <Text color={GRAY} dimColor wrap="wrap">{s.detail}</Text>
          </Box>
        </Box>
      ))}
    </Box>
  );
}

// ── Main ──

export function ScanUI({ stages, summary, thinking, exitHint, verbose = false }: ScanUIProps) {
  return (
    <Box flexDirection="column">
      {stages.map((stage) => (
        <StageRow key={stage.id} stage={stage} verbose={verbose} />
      ))}
      {thinking && (
        <Box marginLeft={6}>
          <Text color={GRAY} dimColor wrap={verbose ? "wrap" : "truncate"}>
            {verbose ? thinking : thinking.slice(-80)}
          </Text>
        </Box>
      )}
      {summary && <SummaryBar summary={summary} />}
      {summary && <OutcomeBlock stages={stages} />}
      <Box marginTop={1} marginLeft={2} gap={2}>
        <Text color={GRAY} dimColor>
          {verbose ? "verbose on" : "v / ctrl+o"} {verbose ? "" : "verbose"}
        </Text>
        {summary && exitHint && (
          <Text color={GRAY} dimColor>{exitHint}</Text>
        )}
      </Box>
    </Box>
  );
}
