import type { SemgrepFinding, NpmAuditFinding } from "@pwnkit/shared";
import type { ScanListener } from "./scanner.js";
import type { PrepareResult } from "./prepare.js";
import { runSemgrepScan } from "./shared-analysis.js";
import { runDependencyAuditForEcosystem } from "./package-ecosystems.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StaticAnalysisResult {
  semgrepFindings: SemgrepFinding[];
  npmAuditFindings: NpmAuditFinding[];
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Run static analysis tools against a prepared target.
 *
 * - npm-package / pypi-package / cargo-package: semgrep + dependency audit
 * - source-code: semgrep only
 * - url / web-app: skip (return empty results)
 */
export async function runStaticAnalysis(
  prepared: PrepareResult,
  emit: ScanListener,
): Promise<StaticAnalysisResult> {
  switch (prepared.targetType) {
    case "npm-package": {
      const semgrepFindings = runSemgrepScan(prepared.resolvedTarget, emit, {
        noGitIgnore: true,
      });
      const npmAuditFindings = prepared.packageInfo
        ? runDependencyAuditForEcosystem(prepared.packageInfo.ecosystem, prepared.packageInfo.tempDir, emit)
        : [];
      return { semgrepFindings, npmAuditFindings };
    }

    case "pypi-package": {
      const semgrepFindings = runSemgrepScan(prepared.resolvedTarget, emit, {
        noGitIgnore: true,
      });
      const npmAuditFindings = prepared.packageInfo
        ? runDependencyAuditForEcosystem(prepared.packageInfo.ecosystem, prepared.packageInfo.tempDir, emit)
        : [];
      return { semgrepFindings, npmAuditFindings };
    }

    case "cargo-package": {
      const semgrepFindings = runSemgrepScan(prepared.resolvedTarget, emit, {
        noGitIgnore: true,
      });
      const npmAuditFindings = prepared.packageInfo
        ? runDependencyAuditForEcosystem(prepared.packageInfo.ecosystem, prepared.packageInfo.tempDir, emit)
        : [];
      return { semgrepFindings, npmAuditFindings };
    }

    case "source-code": {
      const semgrepFindings = runSemgrepScan(prepared.resolvedTarget, emit);
      return { semgrepFindings, npmAuditFindings: [] };
    }

    case "url":
    case "web-app": {
      return { semgrepFindings: [], npmAuditFindings: [] };
    }

    default: {
      const _exhaustive: never = prepared.targetType;
      throw new Error(`Unknown target type: ${_exhaustive}`);
    }
  }
}
