import type {
  ScanContext,
  StageResult,
  Finding,
  AttackResult,
  FindingStatus,
} from "@nightfang/shared";
import { loadTemplateById } from "@nightfang/templates";

export interface VerifyResult {
  findings: Finding[];
  falsePositives: number;
  confirmed: number;
}

export async function runVerification(
  ctx: ScanContext
): Promise<StageResult<VerifyResult>> {
  const start = Date.now();
  const findings: Finding[] = [];
  let falsePositives = 0;
  let confirmed = 0;

  // Group attack results by template
  const resultsByTemplate = new Map<string, AttackResult[]>();
  for (const result of ctx.attacks) {
    const existing = resultsByTemplate.get(result.templateId) ?? [];
    existing.push(result);
    resultsByTemplate.set(result.templateId, existing);
  }

  for (const [templateId, results] of resultsByTemplate) {
    const vulnerableResults = results.filter((r) => r.outcome === "vulnerable");
    if (vulnerableResults.length === 0) continue;

    const template = loadTemplateById(templateId);
    if (!template) continue;

    // Simple verification: if multiple payloads hit, higher confidence
    const status: FindingStatus =
      vulnerableResults.length > 1 ? "confirmed" : "discovered";

    if (status === "confirmed") confirmed++;

    const bestEvidence = vulnerableResults[0];

    const finding: Finding = {
      id: `finding-${templateId}-${Date.now()}`,
      templateId,
      title: `${template.name} — ${template.category}`,
      description: template.description,
      severity: template.severity,
      category: template.category,
      status,
      evidence: {
        request: bestEvidence.request,
        response: bestEvidence.response,
        analysis: `${vulnerableResults.length}/${results.length} payloads triggered vulnerable response patterns.`,
      },
      timestamp: Date.now(),
    };

    findings.push(finding);
    ctx.findings.push(finding);
  }

  return {
    stage: "verify",
    success: true,
    data: { findings, falsePositives, confirmed },
    durationMs: Date.now() - start,
  };
}
