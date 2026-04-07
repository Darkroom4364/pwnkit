/**
 * Pure reducers and selectors for the scan TUI's stage state.
 *
 * These helpers live in @pwnkit/core (instead of @pwnkit/cli) because they are
 * pure TypeScript — no Ink, no React, no side effects — and because that
 * lets us test them in the existing vitest setup without spinning up a
 * separate test harness for the CLI package.
 *
 * The CLI's renderScan.ts wires these into its event loop; ScanUI.tsx uses
 * them at render time to decide how much detail to show based on the
 * verbose toggle.
 */

/** Caps for memory and display. Tuned for pwnkit's per-scan event volume. */
export const STAGE_ACTION_HISTORY_CAP = 500;
export const VERBOSE_ACTIONS_RENDER_CAP = 40;
export const COMPACT_ACTIONS_RENDER_CAP = 3;
export const COMPACT_ACTION_CHARS = 60;
export const VERBOSE_ACTION_CHARS = 120;

/**
 * Clean a raw scan event message for display as a stage action. Strips
 * the repetitive prefixes the scanner emits on every turn so the TUI
 * doesn't show "Discovery turn 1: ...", "Discovery turn 2: ..." etc.
 *
 * Returns an empty string if the message is effectively blank after
 * cleaning; callers should drop empty actions instead of storing them.
 */
export function normalizeStageAction(msg: string): string {
  return msg
    .replace(/^(Discovery|Attack|Verify)\s*turn\s*\d+:\s*/i, "")
    .replace(/^Warning:\s*/i, "")
    .trim();
}

/**
 * Append a new action to a stage's action history, bounded by
 * STAGE_ACTION_HISTORY_CAP. The cap drops the oldest entries rather than
 * rejecting new ones so the verbose view always shows the most recent
 * turns regardless of how long the scan has been running.
 *
 * Returns a new array (never mutates the input).
 */
export function appendStageAction(actions: readonly string[], action: string): string[] {
  if (!action) return actions.slice();
  const next = [...actions, action];
  if (next.length > STAGE_ACTION_HISTORY_CAP) {
    return next.slice(next.length - STAGE_ACTION_HISTORY_CAP);
  }
  return next;
}

/**
 * Truncate a single action to the appropriate width for the current view
 * mode. Compact mode uses a short fixed width so the stage row never
 * wraps; verbose mode allows a much wider line because the user has
 * explicitly asked for detail.
 */
export function truncateStageAction(action: string, verbose: boolean): string {
  const limit = verbose ? VERBOSE_ACTION_CHARS : COMPACT_ACTION_CHARS;
  if (action.length <= limit) return action;
  return action.slice(0, limit) + "...";
}

export interface VisibleActions {
  shown: string[];
  hiddenCount: number;
}

/**
 * Select which actions to render given the current verbose toggle. Returns
 * both the visible tail of the history and the count of earlier actions
 * that were elided, so the UI can show a "… N earlier actions hidden"
 * breadcrumb in compact mode and a larger scroll in verbose mode.
 */
export function selectVisibleActions(
  actions: readonly string[],
  verbose: boolean,
): VisibleActions {
  const cap = verbose ? VERBOSE_ACTIONS_RENDER_CAP : COMPACT_ACTIONS_RENDER_CAP;
  const shown = actions.length <= cap ? actions.slice() : actions.slice(actions.length - cap);
  return { shown, hiddenCount: actions.length - shown.length };
}
