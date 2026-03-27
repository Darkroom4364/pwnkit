import type { ScanContext, StageResult, TargetInfo } from "@nightfang/shared";
import { sendPrompt, extractResponseText } from "../http.js";

export interface DiscoveryResult {
  target: TargetInfo;
}

export async function runDiscovery(
  ctx: ScanContext
): Promise<StageResult<DiscoveryResult>> {
  const start = Date.now();

  try {
    // Probe the target with a simple message to identify its type
    const probeRes = await sendPrompt(ctx.config.target, "Hello, what can you help me with?", {
      timeout: ctx.config.timeout,
    });

    const responseText = extractResponseText(probeRes.body);
    const targetInfo: TargetInfo = {
      url: ctx.config.target,
      type: detectTargetType(responseText, probeRes.status),
      detectedFeatures: detectFeatures(responseText),
    };

    // Try to detect if there's a system prompt by analyzing the response style
    if (responseText.length > 0 && probeRes.status >= 200 && probeRes.status < 300) {
      targetInfo.model = detectModel(responseText, probeRes.headers);
    }

    ctx.target = targetInfo;

    return {
      stage: "discovery",
      success: true,
      data: { target: targetInfo },
      durationMs: Date.now() - start,
    };
  } catch (err) {
    return {
      stage: "discovery",
      success: false,
      data: {
        target: {
          url: ctx.config.target,
          type: "unknown",
        },
      },
      durationMs: Date.now() - start,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

function detectTargetType(
  response: string,
  status: number
): TargetInfo["type"] {
  if (status >= 400) return "unknown";
  const lower = response.toLowerCase();
  if (lower.includes("tool") || lower.includes("function") || lower.includes("mcp"))
    return "agent";
  if (lower.includes("chat") || lower.includes("conversation") || lower.includes("assist"))
    return "chatbot";
  return "api";
}

function detectFeatures(response: string): string[] {
  const features: string[] = [];
  const lower = response.toLowerCase();
  if (lower.includes("code")) features.push("code-generation");
  if (lower.includes("search") || lower.includes("browse")) features.push("web-search");
  if (lower.includes("image") || lower.includes("picture")) features.push("image-generation");
  if (lower.includes("file") || lower.includes("document")) features.push("file-processing");
  if (lower.includes("tool") || lower.includes("function")) features.push("tool-use");
  return features;
}

function detectModel(
  _response: string,
  headers: Record<string, string>
): string | undefined {
  // Check common headers for model info
  const modelHeader =
    headers["x-model"] ||
    headers["x-model-id"] ||
    headers["openai-model"];
  if (modelHeader) return modelHeader;
  return undefined;
}
