import type { Runtime, RuntimeConfig, RuntimeContext, RuntimeResult } from "./types.js";
import { sendPrompt, extractResponseText } from "../http.js";

export class ApiRuntime implements Runtime {
  readonly type = "api" as const;
  private config: RuntimeConfig;

  constructor(config: RuntimeConfig) {
    this.config = config;
  }

  async execute(prompt: string, context?: RuntimeContext): Promise<RuntimeResult> {
    const start = Date.now();
    const target = context?.target ?? "";

    if (!target) {
      return {
        output: "",
        exitCode: 1,
        timedOut: false,
        durationMs: Date.now() - start,
        error: "No target URL provided for API runtime",
      };
    }

    try {
      const res = await sendPrompt(target, prompt, {
        timeout: this.config.timeout,
      });
      const text = extractResponseText(res.body);
      return {
        output: text,
        exitCode: 0,
        timedOut: false,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const timedOut = msg.includes("abort") || msg.includes("timeout");
      return {
        output: "",
        exitCode: 1,
        timedOut,
        durationMs: Date.now() - start,
        error: msg,
      };
    }
  }

  async isAvailable(): Promise<boolean> {
    return true;
  }
}
