import { describe, expect, it } from "vitest";
import {
  appendStageAction,
  normalizeStageAction,
  selectVisibleActions,
  truncateStageAction,
  COMPACT_ACTIONS_RENDER_CAP,
  VERBOSE_ACTIONS_RENDER_CAP,
  COMPACT_ACTION_CHARS,
  VERBOSE_ACTION_CHARS,
  STAGE_ACTION_HISTORY_CAP,
} from "./scan-ui-state.js";

describe("normalizeStageAction", () => {
  it("strips 'Discovery turn N:' prefix", () => {
    expect(normalizeStageAction("Discovery turn 5: probing endpoint"))
      .toBe("probing endpoint");
  });

  it("strips 'Attack turn N:' prefix", () => {
    expect(normalizeStageAction("Attack turn 12: sending payload"))
      .toBe("sending payload");
  });

  it("strips 'Verify turn N:' prefix", () => {
    expect(normalizeStageAction("Verify turn 3: replay 200 OK"))
      .toBe("replay 200 OK");
  });

  it("strips the 'Warning:' prefix", () => {
    expect(normalizeStageAction("Warning: codex is experimental"))
      .toBe("codex is experimental");
  });

  it("returns an empty string for blank inputs so callers drop them", () => {
    expect(normalizeStageAction("")).toBe("");
    expect(normalizeStageAction("   ")).toBe("");
    expect(normalizeStageAction("Discovery turn 1:  ")).toBe("");
  });

  it("leaves already-clean messages untouched", () => {
    expect(normalizeStageAction("sql_inject exploiting login form"))
      .toBe("sql_inject exploiting login form");
  });
});

describe("appendStageAction", () => {
  it("appends a new action to an empty history", () => {
    expect(appendStageAction([], "first")).toEqual(["first"]);
  });

  it("preserves insertion order when appending", () => {
    const s = appendStageAction(appendStageAction([], "a"), "b");
    expect(s).toEqual(["a", "b"]);
  });

  it("does not mutate the input array", () => {
    const original = ["a", "b"];
    const copy = [...original];
    appendStageAction(original, "c");
    expect(original).toEqual(copy);
  });

  it("silently drops empty actions (so the UI doesn't render blank rows)", () => {
    expect(appendStageAction(["a"], "")).toEqual(["a"]);
  });

  it("enforces STAGE_ACTION_HISTORY_CAP by dropping the oldest entries", () => {
    // Build a history one over the cap; the oldest entry should be evicted.
    let history: string[] = [];
    for (let i = 0; i < STAGE_ACTION_HISTORY_CAP + 1; i++) {
      history = appendStageAction(history, `action-${i}`);
    }
    expect(history.length).toBe(STAGE_ACTION_HISTORY_CAP);
    // The most recent entry must still be present.
    expect(history[history.length - 1]).toBe(`action-${STAGE_ACTION_HISTORY_CAP}`);
    // The oldest entry (action-0) must have been dropped.
    expect(history[0]).toBe("action-1");
  });
});

describe("truncateStageAction", () => {
  it("returns short strings unchanged in compact mode", () => {
    const short = "sql_inject";
    expect(truncateStageAction(short, false)).toBe(short);
  });

  it("returns short strings unchanged in verbose mode", () => {
    const short = "sql_inject";
    expect(truncateStageAction(short, true)).toBe(short);
  });

  it("truncates to COMPACT_ACTION_CHARS in compact mode with an ellipsis", () => {
    const long = "a".repeat(COMPACT_ACTION_CHARS + 20);
    const out = truncateStageAction(long, false);
    expect(out.length).toBe(COMPACT_ACTION_CHARS + 3); // "..." suffix
    expect(out.endsWith("...")).toBe(true);
  });

  it("truncates to VERBOSE_ACTION_CHARS in verbose mode with an ellipsis", () => {
    const long = "a".repeat(VERBOSE_ACTION_CHARS + 50);
    const out = truncateStageAction(long, true);
    expect(out.length).toBe(VERBOSE_ACTION_CHARS + 3);
    expect(out.endsWith("...")).toBe(true);
  });

  it("verbose mode preserves strings that compact mode would truncate", () => {
    // A string between the two caps should pass through verbose mode and
    // get clipped in compact mode.
    const len = Math.floor((COMPACT_ACTION_CHARS + VERBOSE_ACTION_CHARS) / 2);
    const s = "x".repeat(len);
    expect(truncateStageAction(s, true)).toBe(s);
    expect(truncateStageAction(s, false).endsWith("...")).toBe(true);
  });
});

describe("selectVisibleActions", () => {
  it("shows all actions and reports 0 hidden when under the compact cap", () => {
    const actions = ["a", "b"];
    const r = selectVisibleActions(actions, false);
    expect(r.shown).toEqual(["a", "b"]);
    expect(r.hiddenCount).toBe(0);
  });

  it("in compact mode shows only the most recent COMPACT_ACTIONS_RENDER_CAP items", () => {
    const actions = ["a", "b", "c", "d", "e"];
    const r = selectVisibleActions(actions, false);
    expect(r.shown).toEqual(actions.slice(actions.length - COMPACT_ACTIONS_RENDER_CAP));
    expect(r.hiddenCount).toBe(actions.length - COMPACT_ACTIONS_RENDER_CAP);
  });

  it("in verbose mode shows up to VERBOSE_ACTIONS_RENDER_CAP items", () => {
    const actions = Array.from({ length: VERBOSE_ACTIONS_RENDER_CAP + 10 }, (_, i) => `a${i}`);
    const r = selectVisibleActions(actions, true);
    expect(r.shown.length).toBe(VERBOSE_ACTIONS_RENDER_CAP);
    // Most recent entries must win.
    expect(r.shown[r.shown.length - 1]).toBe(`a${actions.length - 1}`);
    expect(r.hiddenCount).toBe(10);
  });

  it("returns a fresh array so callers can safely mutate", () => {
    const actions = ["x", "y", "z"];
    const r = selectVisibleActions(actions, false);
    expect(r.shown).not.toBe(actions);
  });

  it("regression: verbose mode reveals actions hidden in compact mode", () => {
    // This is the whole point of the toggle: a user hits `v` mid-scan and
    // expects to see the full turn history, not just the last three.
    const actions = Array.from({ length: 20 }, (_, i) => `turn-${i}`);
    const compact = selectVisibleActions(actions, false);
    const verbose = selectVisibleActions(actions, true);
    expect(compact.shown.length).toBe(COMPACT_ACTIONS_RENDER_CAP);
    expect(verbose.shown.length).toBe(20);
    expect(verbose.shown.length).toBeGreaterThan(compact.shown.length);
    // Every entry visible in compact mode must also be present in verbose.
    for (const entry of compact.shown) {
      expect(verbose.shown).toContain(entry);
    }
  });
});
