import { describe, expect, it } from "vitest";
import { PLAYBOOKS, buildPlaybookInjection, detectPlaybooks } from "./playbooks.js";

describe("PLAYBOOKS — XBEN-054 HTTP method tampering hint", () => {
  it("auth_bypass playbook mentions BOGUS, Limit, and XBEN-054", () => {
    const auth = PLAYBOOKS.auth_bypass;
    expect(auth).toBeDefined();
    expect(auth).toContain("BOGUS");
    expect(auth).toContain("Limit");
    expect(auth).toContain("XBEN-054");
  });

  it("auth_bypass hint references Apache and non-standard HTTP verbs", () => {
    const auth = PLAYBOOKS.auth_bypass;
    expect(auth).toMatch(/Apache/);
    expect(auth).toMatch(/HTTP basic auth|basic auth/i);
  });
});

describe("PLAYBOOKS — XBEN-010 JSFuck XSS hint", () => {
  it("xss playbook references JSFuck and the payload lookup helper", () => {
    const xss = PLAYBOOKS.xss;
    expect(xss).toBeDefined();
    expect(xss).toContain("JSFuck");
    expect(xss).toContain("payload_lookup");
    expect(xss).toContain("jsfuck_xss");
    expect(xss).toContain("XBEN-010");
  });

  it("xss hint mentions the six allowed characters", () => {
    const xss = PLAYBOOKS.xss;
    expect(xss).toContain("[]()!+");
  });
});

describe("buildPlaybookInjection / detectPlaybooks (smoke)", () => {
  it("returns empty string when no types provided", () => {
    expect(buildPlaybookInjection([])).toBe("");
  });

  it("includes the auth_bypass section when requested", () => {
    const injection = buildPlaybookInjection(["auth_bypass"]);
    expect(injection).toContain("Auth Bypass Playbook");
    expect(injection).toContain("XBEN-054");
  });

  it("detectPlaybooks returns an array", () => {
    const out = detectPlaybooks(["plain text with no indicators"]);
    expect(Array.isArray(out)).toBe(true);
  });
});
