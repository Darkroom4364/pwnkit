import type {
  ScanContext,
  StageResult,
  AttackTemplate,
  AttackResult,
  AttackOutcome,
} from "@nightfang/shared";
import { DEPTH_CONFIG } from "@nightfang/shared";
import { sendPrompt, extractResponseText } from "../http.js";

export interface AttackStageResult {
  results: AttackResult[];
  templatesRun: number;
  payloadsRun: number;
}

export async function runAttacks(
  ctx: ScanContext,
  templates: AttackTemplate[]
): Promise<StageResult<AttackStageResult>> {
  const start = Date.now();
  const results: AttackResult[] = [];
  const depthCfg = DEPTH_CONFIG[ctx.config.depth];

  // Limit templates based on depth
  const templatesToRun = templates.slice(0, depthCfg.maxTemplates);
  let payloadsRun = 0;

  for (const template of templatesToRun) {
    const payloads = template.payloads.slice(0, depthCfg.maxPayloadsPerTemplate);

    for (const payload of payloads) {
      payloadsRun++;
      try {
        const res = await sendPrompt(ctx.config.target, payload.prompt, {
          timeout: ctx.config.timeout,
        });

        const responseText = extractResponseText(res.body);
        const outcome = evaluateResponse(responseText, template);

        const result: AttackResult = {
          templateId: template.id,
          payloadId: payload.id,
          outcome,
          request: payload.prompt,
          response: responseText,
          latencyMs: res.latencyMs,
          timestamp: Date.now(),
        };

        results.push(result);
        ctx.attacks.push(result);
      } catch (err) {
        const result: AttackResult = {
          templateId: template.id,
          payloadId: payload.id,
          outcome: "error",
          request: payload.prompt,
          response: "",
          latencyMs: 0,
          timestamp: Date.now(),
          error: err instanceof Error ? err.message : String(err),
        };
        results.push(result);
        ctx.attacks.push(result);
      }
    }
  }

  return {
    stage: "attack",
    success: true,
    data: {
      results,
      templatesRun: templatesToRun.length,
      payloadsRun,
    },
    durationMs: Date.now() - start,
  };
}

function evaluateResponse(
  response: string,
  template: AttackTemplate
): AttackOutcome {
  const { detection } = template;

  // Check for vulnerable patterns
  for (const pattern of detection.vulnerablePatterns) {
    try {
      const re = new RegExp(pattern, "i");
      if (re.test(response)) return "vulnerable";
    } catch {
      // Invalid regex, skip
    }
  }

  // Check for safe patterns
  if (detection.safePatterns) {
    for (const pattern of detection.safePatterns) {
      try {
        const re = new RegExp(pattern, "i");
        if (re.test(response)) return "safe";
      } catch {
        // Invalid regex, skip
      }
    }
  }

  return "inconclusive";
}
