/** Approximate cost per 1M tokens by provider/model */
const PRICING: Record<string, { input: number; output: number }> = {
  // OpenAI
  "gpt-5.4": { input: 2.50, output: 10.00 },
  "gpt-4o": { input: 2.50, output: 10.00 },
  "gpt-4.1": { input: 2.00, output: 8.00 },
  "gpt-4.1-mini": { input: 0.40, output: 1.60 },
  "gpt-4.1-nano": { input: 0.10, output: 0.40 },
  "o3": { input: 10.00, output: 40.00 },
  "o4-mini": { input: 1.10, output: 4.40 },
  // Anthropic
  "claude-sonnet-4-6": { input: 3.00, output: 15.00 },
  "claude-opus-4-6": { input: 15.00, output: 75.00 },
  "claude-haiku-4-5": { input: 0.80, output: 4.00 },
  // Google
  "gemini-2.5-pro": { input: 1.25, output: 10.00 },
  "gemini-2.5-flash": { input: 0.15, output: 0.60 },
  // DeepSeek
  "deepseek-r1": { input: 0.55, output: 2.19 },
  "deepseek-v3": { input: 0.27, output: 1.10 },
  // Meta
  "llama-4-maverick": { input: 0.50, output: 0.77 },
  "llama-4-scout": { input: 0.27, output: 0.35 },
  // Mistral
  "mistral-large": { input: 2.00, output: 6.00 },
  "mistral-small": { input: 0.10, output: 0.30 },
  "codestral": { input: 0.30, output: 0.90 },
  default: { input: 3.00, output: 15.00 },
};

/** Strip vendor prefixes (e.g. "anthropic/claude-sonnet-4-6" → "claude-sonnet-4-6") */
function normalizeModel(model: string): string {
  const slash = model.lastIndexOf("/");
  return slash === -1 ? model : model.slice(slash + 1);
}

export function estimateCost(
  usage: { inputTokens: number; outputTokens: number },
  model?: string,
): number {
  const key = model ? normalizeModel(model) : "";
  const rates = PRICING[key] ?? PRICING.default;
  if (model && !PRICING[key]) {
    console.warn(`[pwnkit] Unknown model "${model}", using default pricing`);
  }
  return (
    (usage.inputTokens / 1_000_000) * rates.input +
    (usage.outputTokens / 1_000_000) * rates.output
  );
}
