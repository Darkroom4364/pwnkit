import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { pwnkitDB } from "@pwnkit/db";
import type { Finding, ScanConfig } from "@pwnkit/shared";

const tempDirs: string[] = [];

function makeDb(): { db: pwnkitDB; scanId: string } {
  const dir = mkdtempSync(join(tmpdir(), "pwnkit-triage-persist-"));
  tempDirs.push(dir);
  const db = new pwnkitDB(join(dir, "pwnkit.db"));
  const scanConfig: ScanConfig = {
    target: "http://example.test",
    depth: "default",
    format: "json",
    runtime: "api",
    mode: "deep",
  };
  const scanId = db.createScan(scanConfig);
  return { db, scanId };
}

function makeFinding(): Finding {
  return {
    id: randomUUID(),
    templateId: "manual",
    title: "Reflected XSS",
    description: "raw finding",
    severity: "high",
    category: "xss",
    status: "discovered",
    evidence: {
      request: "POST /page",
      response: "<script>alert(1)</script>",
      analysis: "initial evidence",
    },
    timestamp: Date.now(),
  };
}

describe("triage persistence", () => {
  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("persists triage fields when a finding is re-saved after triage", () => {
    const { db, scanId } = makeDb();
    try {
      const finding = makeFinding();
      db.saveFinding(scanId, finding);

      finding.severity = "info";
      finding.status = "false-positive";
      finding.triageStatus = "suppressed";
      finding.triageNote = "rejected: holding-it-wrong";
      finding.evidence.analysis = "updated after triage";

      db.saveFinding(scanId, finding);

      const persisted = db.getFinding(finding.id);
      expect(persisted?.severity).toBe("info");
      expect(persisted?.status).toBe("false-positive");
      expect(persisted?.triageStatus).toBe("suppressed");
      expect(persisted?.triageNote).toBe("rejected: holding-it-wrong");
      expect(persisted?.evidenceAnalysis).toBe("updated after triage");
      expect(persisted?.triagedAt).toBeTruthy();
    } finally {
      db.close();
    }
  });
});
