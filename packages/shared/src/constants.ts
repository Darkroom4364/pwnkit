// IMPORTANT: keep in lockstep with the root package.json "version" field.
// The CLI surfaces this constant via `pwnkit-cli --version`, while npm
// reads the package.json. v0.7.1 shipped to npm with a stale "0.7.0" here
// because only package.json was bumped — the version-sync.test.ts case
// in this package fails the build if they ever drift again.
export const VERSION = "0.7.2";

export const DEFAULT_MODEL = "claude-sonnet-4-20250514";
export const DEFAULT_TIMEOUT_MS = 30_000;
export const DEFAULT_MAX_CONCURRENCY = 5;

export const DEPTH_CONFIG = {
  quick: { maxTemplates: 5, maxPayloadsPerTemplate: 1, multiTurn: false },
  default: { maxTemplates: 20, maxPayloadsPerTemplate: 3, multiTurn: false },
  deep: { maxTemplates: Infinity, maxPayloadsPerTemplate: Infinity, multiTurn: true },
} as const;

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};
