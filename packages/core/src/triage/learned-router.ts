/**
 * Learned Triage Router — v1 hand-coded rules derived from XGBoost
 *
 * The XGBoost model trained on triage-dataset-v2.jsonl (1514 rows) found
 * that per-slice classifiers beat any single mixed-data model. The top
 * features by slice are:
 *
 *   - xbow white-box: meta_confidence, req_param_count, evidence_completeness
 *   - xbow black-box: cross_response_request_length_ratio, meta_injection_class
 *   - npm-bench: text_description_length, text_analysis_length
 *
 * This module implements the auto-accept / auto-reject thresholds the
 * XGBoost model learned, as hand-coded TypeScript rules. It's Option 2
 * from the dynamic routing design doc — ships today, zero deps, sub-ms.
 *
 * The full XGBoost JSON model is at packages/benchmark/results/triage-router-v1.json
 * for anyone who wants to integrate via ONNX or a JS tree evaluator.
 *
 * Feature flag: PWNKIT_FEATURE_LEARNED_ROUTER (default OFF).
 * See pwnkit#113 for the design doc and pwnkit#72 for the ablation data.
 */

import type { Finding, Severity, TriageLayerName } from "@pwnkit/shared";
import { extractFeatures, FEATURE_NAMES } from "./feature-extractor.js";

export type RouterDecision = "auto_accept" | "auto_reject" | "run_layers";

export interface RouterResult {
  decision: RouterDecision;
  confidence: number;
  reason: string;
  /** Which layers to run if decision === "run_layers". Empty otherwise. */
  layersToRun: TriageLayerName[];
  /** Which layers to skip. Inverse of layersToRun. */
  layersToSkip: TriageLayerName[];
}

type SliceType = "xbow-wb" | "xbow-bb" | "npm" | "unknown";

const ALL_TRIAGE_LAYERS: TriageLayerName[] = [
  "holding_it_wrong",
  "evidence_gate",
  "reachability",
  "multi_modal",
  "oracle",
  "pov_gate",
];

const FREE_LAYERS: TriageLayerName[] = [
  "holding_it_wrong",
  "evidence_gate",
  "oracle",
];

const EXPENSIVE_LAYERS: TriageLayerName[] = [
  "reachability",
  "multi_modal",
  "pov_gate",
];

function featureByName(features: number[], name: string): number {
  const idx = FEATURE_NAMES.indexOf(name);
  return idx >= 0 ? features[idx] ?? 0 : 0;
}

/**
 * Route a finding through the learned triage rules.
 *
 * @param finding - The finding to triage.
 * @param sliceType - The scan context ("xbow-wb", "xbow-bb", "npm", "unknown").
 *   The scanner knows this at startup from the target type and mode.
 * @returns RouterResult with the decision and which layers to run.
 */
export function routeFinding(
  finding: Finding,
  sliceType: SliceType = "unknown",
): RouterResult {
  const features = extractFeatures(finding);
  const confidence = finding.confidence ?? featureByName(features, "meta_confidence");
  const evidenceCompleteness = featureByName(features, "cross_evidence_completeness");
  const hedging = featureByName(features, "text_hedging_language");
  const verification = featureByName(features, "text_verification_language");
  const descriptionLength = featureByName(features, "text_description_length");
  const analysisLength = featureByName(features, "text_analysis_length");
  const respReqRatio = featureByName(features, "cross_response_request_length_ratio");
  const injectionClass = featureByName(features, "meta_injection_class");

  // --- Auto-reject rules (universal across slices) ---

  if (evidenceCompleteness <= 0.33 && confidence < 0.3) {
    return {
      decision: "auto_reject",
      confidence: 0.9,
      reason: `low evidence (${evidenceCompleteness.toFixed(2)}) + low confidence (${confidence.toFixed(2)})`,
      layersToRun: [],
      layersToSkip: ALL_TRIAGE_LAYERS,
    };
  }

  // --- Per-slice routing ---

  if (sliceType === "npm") {
    return routeNpm(features, finding, confidence, descriptionLength, analysisLength, respReqRatio);
  }
  if (sliceType === "xbow-bb") {
    return routeBlackBox(features, finding, confidence, respReqRatio, injectionClass);
  }
  if (sliceType === "xbow-wb") {
    return routeWhiteBox(features, finding, confidence, evidenceCompleteness, hedging, verification);
  }

  // Unknown slice — fall back to conservative white-box rules
  return routeWhiteBox(features, finding, confidence, evidenceCompleteness, hedging, verification);
}

function routeWhiteBox(
  _features: number[],
  _finding: Finding,
  confidence: number,
  evidenceCompleteness: number,
  hedging: number,
  verification: number,
): RouterResult {
  // XGBoost wb model: 82% of findings auto-accepted at threshold 0.536.
  // The top features are meta_confidence and evidence_completeness.
  // Hand-coded proxy: high confidence + good evidence + no hedging = accept.
  if (confidence >= 0.8 && evidenceCompleteness >= 0.66 && !hedging && verification) {
    return {
      decision: "auto_accept",
      confidence: 0.92,
      reason: `wb: high confidence (${confidence.toFixed(2)}) + complete evidence + verification language`,
      layersToRun: [],
      layersToSkip: ALL_TRIAGE_LAYERS,
    };
  }

  if (confidence >= 0.7 && evidenceCompleteness >= 0.66) {
    // Moderate confidence — run only the free layers, skip expensive ones
    return {
      decision: "run_layers",
      confidence: 0.75,
      reason: `wb: moderate confidence (${confidence.toFixed(2)}), skipping expensive layers`,
      layersToRun: FREE_LAYERS,
      layersToSkip: EXPENSIVE_LAYERS,
    };
  }

  // Low confidence or thin evidence — run everything
  return {
    decision: "run_layers",
    confidence: 0.5,
    reason: "wb: uncertain, running full pipeline",
    layersToRun: ALL_TRIAGE_LAYERS,
    layersToSkip: [],
  };
}

function routeBlackBox(
  _features: number[],
  _finding: Finding,
  confidence: number,
  respReqRatio: number,
  injectionClass: number,
): RouterResult {
  // XGBoost bb model: 92% auto-accepted. Top feature is response/request
  // length ratio. FPs tend to have injection-class findings with high ratios.
  if (injectionClass && respReqRatio > 4 && confidence < 0.6) {
    return {
      decision: "run_layers",
      confidence: 0.4,
      reason: `bb: injection-class + high resp/req ratio (${respReqRatio.toFixed(1)}) + low confidence`,
      layersToRun: ALL_TRIAGE_LAYERS,
      layersToSkip: [],
    };
  }

  // Most bb findings are TP — auto-accept unless flagged above
  if (confidence >= 0.5) {
    return {
      decision: "auto_accept",
      confidence: 0.85,
      reason: `bb: moderate+ confidence (${confidence.toFixed(2)}), auto-accepting`,
      layersToRun: [],
      layersToSkip: ALL_TRIAGE_LAYERS,
    };
  }

  return {
    decision: "run_layers",
    confidence: 0.5,
    reason: "bb: low confidence, running layers",
    layersToRun: FREE_LAYERS,
    layersToSkip: EXPENSIVE_LAYERS,
  };
}

function routeNpm(
  _features: number[],
  _finding: Finding,
  confidence: number,
  descriptionLength: number,
  analysisLength: number,
  respReqRatio: number,
): RouterResult {
  // XGBoost npm model: text_description_length dominates (50%).
  // FPs have LONGER descriptions (mean 1071) than TPs (mean 580).
  // FPs also have longer analysis (529 vs 321) and lower resp/req ratio.
  if (descriptionLength > 900 && analysisLength > 450 && respReqRatio < 2) {
    return {
      decision: "auto_reject",
      confidence: 0.8,
      reason: `npm: long description (${descriptionLength}) + long analysis (${analysisLength}) + low ratio — likely FP`,
      layersToRun: [],
      layersToSkip: ALL_TRIAGE_LAYERS,
    };
  }

  if (descriptionLength < 700 && confidence >= 0.5) {
    return {
      decision: "auto_accept",
      confidence: 0.88,
      reason: `npm: concise description (${descriptionLength}) + confidence ${confidence.toFixed(2)}`,
      layersToRun: [],
      layersToSkip: ALL_TRIAGE_LAYERS,
    };
  }

  return {
    decision: "run_layers",
    confidence: 0.5,
    reason: "npm: ambiguous, running free layers only",
    layersToRun: FREE_LAYERS,
    layersToSkip: EXPENSIVE_LAYERS,
  };
}
