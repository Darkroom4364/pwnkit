import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { getCloudSinkConfig, postFinding, postFinalReport } from "./cloud-sink.js";

const ENV_KEYS = [
  "PWNKIT_CLOUD_SINK",
  "PWNKIT_CLOUD_SCAN_ID",
  "PWNKIT_CLOUD_TOKEN",
  "PWNKIT_FEATURE_CLOUD_SINK",
];

describe("cloud-sink", () => {
  const originalFetch = globalThis.fetch;
  const savedEnv: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
    for (const k of ENV_KEYS) delete process.env[k];
  });

  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (savedEnv[k] === undefined) delete process.env[k];
      else process.env[k] = savedEnv[k]!;
    }
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("getCloudSinkConfig returns null when env vars are unset", () => {
    expect(getCloudSinkConfig()).toBeNull();
  });

  it("getCloudSinkConfig returns null when only the URL is set", () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    expect(getCloudSinkConfig()).toBeNull();
  });

  it("getCloudSinkConfig returns config when URL + scan id are set", () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-123";
    process.env.PWNKIT_CLOUD_TOKEN = "tok-abc";
    expect(getCloudSinkConfig()).toEqual({
      sinkUrl: "https://api.example.com",
      scanId: "scan-123",
      token: "tok-abc",
    });
  });

  it("postFinding does NOT call fetch when env vars are unset", async () => {
    const fetchMock = vi.fn();
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    await postFinding({ severity: "high", title: "test" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("postFinding POSTs to /scans/<id>/findings with correct headers + body", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com/";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-123";
    process.env.PWNKIT_CLOUD_TOKEN = "tok-abc";

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => "",
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const finding = { severity: "critical", title: "RCE", description: "..." };
    await postFinding(finding);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://api.example.com/scans/scan-123/findings");
    expect(init.method).toBe("POST");
    expect(init.headers["Content-Type"]).toBe("application/json");
    expect(init.headers["X-Pwnkit-Scan-Id"]).toBe("scan-123");
    expect(init.headers["Authorization"]).toBe("Bearer tok-abc");
    expect(JSON.parse(init.body)).toEqual({ finding });
  });

  it("postFinalReport POSTs the final report flag", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-456";

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => "",
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const report = { target: "https://x.test", findings: [], summary: {} };
    await postFinalReport(report);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://api.example.com/scans/scan-456/findings");
    const parsed = JSON.parse(init.body);
    expect(parsed.report).toEqual(report);
    expect(parsed.final).toBe(true);
    // No token configured → no Authorization header
    expect(init.headers["Authorization"]).toBeUndefined();
  });

  it("does NOT throw when sink returns 5xx — local scan continues", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-789";

    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 503,
      text: async () => "service unavailable",
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    // Silence the diagnostic write
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    await expect(postFinding({ title: "x" })).resolves.toBeUndefined();
    await expect(postFinalReport({ target: "x" })).resolves.toBeUndefined();
    expect(stderrSpy).toHaveBeenCalled();
  });

  it("does NOT throw when fetch itself rejects (network error)", async () => {
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-net";

    const fetchMock = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    await expect(postFinding({ title: "x" })).resolves.toBeUndefined();
    expect(stderrSpy).toHaveBeenCalled();
  });

  it("respects PWNKIT_FEATURE_CLOUD_SINK=0 even when URL is set", async () => {
    // Note: features.ts is evaluated at module load, so we have to import a
    // fresh copy to observe the flag change.
    process.env.PWNKIT_CLOUD_SINK = "https://api.example.com";
    process.env.PWNKIT_CLOUD_SCAN_ID = "scan-disabled";
    process.env.PWNKIT_FEATURE_CLOUD_SINK = "0";

    vi.resetModules();
    const mod = await import("./cloud-sink.js");
    expect(mod.getCloudSinkConfig()).toBeNull();

    const fetchMock = vi.fn();
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    await mod.postFinding({ title: "x" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
