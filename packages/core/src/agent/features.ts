/**
 * Feature flags for A/B testing agent improvements.
 * Set via environment variables: PWNKIT_FEATURE_<NAME>=0 to disable.
 *
 * NOTE on defaults:
 *   - "stable" features (early stop, loop detection, context compaction,
 *     script templates) default ON.
 *   - "experimental" features (playbooks, memory, handoff, web search) default OFF.
 *   - "v0.6.0 FP moat layers" (povGate, reachabilityGate, multiModal,
 *     adversarialDebate, triageMemories, egatsTreeSearch,
 *     selfConsistencyVerify) ALSO default OFF — they need explicit enablement
 *     in CI before any FP-moat A/B claim can be made.
 *   - "always-on triage filters" (`holdingItWrong`, `evidenceGate`) default
 *     ON — they're the only filters that ran in every v0.6.0 ablation, so
 *     they need to be ablatable.
 */
export const features = {
  /** Early-stop at 50% budget if no findings, retry with different strategy */
  earlyStopRetry: env("PWNKIT_FEATURE_EARLY_STOP", true),
  /** Detect A-A-A and A-B-A-B loop patterns, inject warning */
  loopDetection: env("PWNKIT_FEATURE_LOOP_DETECTION", true),
  /** Compress middle messages when context exceeds 30k tokens */
  contextCompaction: env("PWNKIT_FEATURE_CONTEXT_COMPACTION", true),
  /** Exploit script templates in shell prompt (blind SQLi, SSTI, auth chain) */
  scriptTemplates: env("PWNKIT_FEATURE_SCRIPT_TEMPLATES", true),
  /** Dynamic vulnerability playbooks injected after recon phase */
  dynamicPlaybooks: env("PWNKIT_FEATURE_DYNAMIC_PLAYBOOKS", false),
  /** Agent writes plan/creds to disk, injected at reflection checkpoints */
  externalMemory: env("PWNKIT_FEATURE_EXTERNAL_MEMORY", false),
  /** Inject prior attempt findings when retrying */
  progressHandoff: env("PWNKIT_FEATURE_PROGRESS_HANDOFF", false),
  /** Allow the agent to search the web for CVE details, docs, and technique references */
  webSearch: env("PWNKIT_FEATURE_WEB_SEARCH", false),
  /** Run bash commands inside a Kali Docker container with full pentesting toolset */
  dockerExecutor: env("PWNKIT_FEATURE_DOCKER_EXECUTOR", false),
  /** Interactive PTY sessions for exploits requiring interactivity (reverse shells, DB clients, SSH) */
  ptySession: env("PWNKIT_FEATURE_PTY_SESSION", false),
  /** EGATS (Evidence-Gated Attack Tree Search) — beam-search exploration of attack hypotheses */
  egatsTreeSearch: env("PWNKIT_FEATURE_EGATS", false),
  /** Self-consistency voting: run the structured verify pipeline N times and take the majority vote */
  selfConsistencyVerify: env("PWNKIT_FEATURE_CONSENSUS_VERIFY", false),
  /** Adversarial debate: prosecutor vs defender agents debate each finding, skeptical judge decides */
  adversarialDebate: env("PWNKIT_FEATURE_DEBATE", false),
  /** Multi-modal agreement: cross-validate findings against foxguard (Rust pattern scanner) */
  multiModalAgreement: env("PWNKIT_FEATURE_MULTIMODAL", false),
  /** Reachability gate: suppress findings whose sink is not reachable from an application entry point */
  reachabilityGate: env("PWNKIT_FEATURE_REACHABILITY_GATE", false),
  /** PoV gate: require a working, executable PoC per finding or downgrade to info */
  povGate: env("PWNKIT_FEATURE_POV_GATE", false),
  /** Semgrep-style per-target persistent FP memories injected into the verify pipeline */
  triageMemories: env("PWNKIT_FEATURE_TRIAGE_MEMORIES", false),
  /**
   * WordPress plugin/theme fingerprinter + OSV CVE lookup.
   * Exposes the `wp_fingerprint` tool to the attack agent. Off by default —
   * opt in via `--features wp_fingerprint` (or PWNKIT_FEATURE_WP_FINGERPRINT=1)
   * when the target is known or suspected to be WordPress. See
   * packages/core/src/agent/wp-fingerprint.ts for the implementation.
   *
   * Implemented as a getter so the CLI `--features` flag — which sets the env
   * var inside the command action, AFTER this module has been imported — is
   * still honored at tool-dispatch time.
   */
  get wpFingerprint(): boolean {
    return env("PWNKIT_FEATURE_WP_FINGERPRINT", false);
  },

  /**
   * MongoDB ObjectID forge tool. Exposes the `mongo_objectid` tool to the
   * attack agent so it can compute valid 24-char hex ObjectIds with arbitrary
   * timestamps + counters (e.g. forge the "first user" ObjectId in an IDOR
   * challenge by setting timestamp = appStartTimestamp and counter = 0).
   *
   * Default ON — this is a pure-computation utility with no network or
   * filesystem side effects, so there's no reason to gate it off. Disable
   * via PWNKIT_FEATURE_MONGO_OBJECTID_FORGE=0 or `--no-mongo-objectid-forge`
   * for ablation. Implemented as a getter so the CLI `--features` flag
   * (which sets the env var inside the command action, AFTER this module
   * has been imported) is still honored at tool-dispatch time. Matches
   * the wpFingerprint pattern above. See packages/core/src/agent/objectid-forge.ts.
   */
  get mongoObjectIdForge(): boolean {
    return env("PWNKIT_FEATURE_MONGO_OBJECTID_FORGE", true);
  },

  /**
   * Anti-honeypot flag-shape validator. When the agent calls the `done`
   * tool with a proposed `FLAG{...}`, the tool runs `validateFlagShape`
   * first; low-confidence ("looks like a decoy") flags are rejected once
   * with a hint to keep exploring. The agent can override by retrying the
   * same flag — the heuristic is a speed bump, not a hard wall.
   *
   * Default ON because legitimate flags pass the shape check trivially
   * and the false-positive rate on real flags should be near zero. Turn
   * off via `PWNKIT_FEATURE_DECOY_DETECTION=0` or the CLI flag
   * `--no-decoy-detection` for ablation/testing.
   *
   * Implemented as a getter so the CLI flag (which flips the env var
   * inside the command action, AFTER this module has been imported) is
   * still honored at tool-dispatch time. Matches the wpFingerprint
   * pattern above. See GitHub issue #82 and
   * packages/core/src/agent/flag-validator.ts.
   */
  get decoyDetection(): boolean {
    return env("PWNKIT_FEATURE_DECOY_DETECTION", true);
  },

  // ── Always-on triage filters (default ON, ablatable for A/B testing) ──

  /**
   * `holding-it-wrong` regex blocklist (`packages/core/src/triage/holding-it-wrong.ts`).
   * Matches finding text against documented I/O / eval / compile / persistence
   * sink names and rejects findings that look like "the function did its job".
   *
   * Default ON because that's the existing v0.6.0 behavior. Can be disabled
   * via PWNKIT_FEATURE_HOLDING_IT_WRONG=0 to test whether this filter is
   * suppressing real signal — the ceiling-analysis from 2026-04-06 identified
   * this as the strongest candidate for the unexplained XBOW finding-density
   * collapse from 14 → 4 between `features=none` and `features=all`.
   */
  holdingItWrong: env("PWNKIT_FEATURE_HOLDING_IT_WRONG", true),

  /**
   * `evidence_completeness <= 0.5` reject (`packages/core/src/agentic-scanner.ts:591`).
   * Drops findings whose extracted feature vector says the agent didn't
   * gather enough cross-source evidence (request + response + analysis + ...).
   *
   * Default ON because that's the existing v0.6.0 behavior. Can be disabled
   * via PWNKIT_FEATURE_EVIDENCE_GATE=0 for ablation.
   */
  evidenceGate: env("PWNKIT_FEATURE_EVIDENCE_GATE", true),

  /**
   * Opt-in cloud-sink webhook integration (`packages/core/src/cloud-sink.ts`).
   * When enabled AND the user has set PWNKIT_CLOUD_SINK + PWNKIT_CLOUD_SCAN_ID,
   * every finding and the final scan report are POSTed to the configured
   * remote endpoint in real time.
   *
   * Default ON so the env-var trio is sufficient to enable streaming, but the
   * flag exists so operators can force-disable the integration in environments
   * where outbound HTTP from the scanner is not desired (e.g. air-gapped CI).
   * Disable via PWNKIT_FEATURE_CLOUD_SINK=0.
   */
  cloudSink: env("PWNKIT_FEATURE_CLOUD_SINK", true),

  /**
   * Pre-recon CVE check (`packages/core/src/pre-recon-cve.ts`).
   * In white-box mode (`--repo` set), runs `npm audit` / `pip-audit`
   * against the source tree before the attack agent starts and injects
   * any high/critical advisories into the system prompt as priority
   * leads. Defends against expensive thrash on CVE-tagged challenges
   * where the agent has source access but no concrete leads.
   *
   * Default ON in white-box mode (no-op in black-box). Disable via
   * PWNKIT_FEATURE_PRE_RECON_CVE=0 for ablation.
   */
  preReconCve: env("PWNKIT_FEATURE_PRE_RECON_CVE", true),
};

function env(key: string, defaultValue: boolean): boolean {
  const val = process.env[key];
  if (val === undefined) return defaultValue;
  return val !== "0" && val !== "false";
}
