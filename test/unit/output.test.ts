import { describe, it, expect } from "vitest";
import { effectiveOutput, formatSendResult, formatReceiveResult } from "../../src/lib/output.js";

describe("effectiveOutput (pipe detection)", () => {
  it("human stays human on a TTY", () => {
    expect(effectiveOutput("human", true)).toBe("human");
  });
  it("human degrades to quiet when stdout is piped", () => {
    expect(effectiveOutput("human", false)).toBe("quiet");
  });
  it("json and quiet are unaffected by TTY state", () => {
    expect(effectiveOutput("json", false)).toBe("json");
    expect(effectiveOutput("json", true)).toBe("json");
    expect(effectiveOutput("quiet", true)).toBe("quiet");
  });
});

const SEND = {
  id: "abcDEF0123456789abcDEF0123456789",
  url: "https://deadrop.dev/s/abcDEF0123456789abcDEF0123456789#KEY",
  ttlMinutes: 60,
  passwordProtected: false,
  expiresAt: new Date("2026-06-12T12:00:00Z"),
};

describe("formatSendResult", () => {
  it("quiet mode prints only the URL", () => {
    expect(formatSendResult(SEND, "quiet")).toBe(SEND.url + "\n");
  });

  it("json mode prints one valid JSON object with plan fields", () => {
    const out = formatSendResult(SEND, "json");
    const obj = JSON.parse(out);
    expect(obj).toEqual({
      id: SEND.id,
      url: SEND.url,
      expires_at: "2026-06-12T12:00:00.000Z",
      ttl: 3600,
      password_protected: false,
    });
  });

  it("human mode includes URL, expiry, and revoke hint", () => {
    const out = formatSendResult(SEND, "human");
    expect(out).toContain(SEND.url);
    expect(out).toContain("1 hour");
    expect(out).toContain("deadrop revoke");
    expect(out).toContain("one-time");
  });
});

describe("formatReceiveResult", () => {
  it("quiet mode prints content exactly (no trailing newline added)", () => {
    expect(formatReceiveResult("secret-stuff", "quiet")).toBe("secret-stuff");
    expect(formatReceiveResult("line\n", "quiet")).toBe("line\n");
  });

  it("json mode prints {content, burned}", () => {
    expect(JSON.parse(formatReceiveResult("x", "json"))).toEqual({
      content: "x",
      burned: true,
    });
  });

  it("human mode decorates and ends with newline", () => {
    const out = formatReceiveResult("my-secret", "human");
    expect(out).toContain("my-secret");
    expect(out).toMatch(/burned/i);
    expect(out.endsWith("\n")).toBe(true);
  });
});
