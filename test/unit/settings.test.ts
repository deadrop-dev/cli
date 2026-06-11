import { describe, it, expect } from "vitest";
import { resolveSettings, DEFAULT_SERVER } from "../../src/lib/settings.js";

describe("resolveSettings precedence: flags > env > config > defaults", () => {
  it("uses defaults when nothing is set", () => {
    const s = resolveSettings({}, {}, {});
    expect(s.server).toBe(DEFAULT_SERVER);
    expect(s.ttlMinutes).toBe(60);
    expect(s.output).toBe("human");
  });

  it("config overrides defaults", () => {
    const s = resolveSettings({}, {}, { server: "https://c.example", "default-ttl": "24h", output: "json" });
    expect(s.server).toBe("https://c.example");
    expect(s.ttlMinutes).toBe(1440);
    expect(s.output).toBe("json");
  });

  it("env overrides config", () => {
    const s = resolveSettings(
      {},
      { DEADROP_SERVER: "https://e.example", DEADROP_TTL: "5m", DEADROP_OUTPUT: "quiet" },
      { server: "https://c.example", "default-ttl": "24h", output: "json" },
    );
    expect(s.server).toBe("https://e.example");
    expect(s.ttlMinutes).toBe(5);
    expect(s.output).toBe("quiet");
  });

  it("flags override env", () => {
    const s = resolveSettings(
      { server: "https://f.example", ttl: "7d", json: true },
      { DEADROP_SERVER: "https://e.example", DEADROP_TTL: "5m", DEADROP_OUTPUT: "human" },
      {},
    );
    expect(s.server).toBe("https://f.example");
    expect(s.ttlMinutes).toBe(10080);
    expect(s.output).toBe("json");
  });

  it("--quiet flag wins over env output", () => {
    const s = resolveSettings({ quiet: true }, { DEADROP_OUTPUT: "json" }, {});
    expect(s.output).toBe("quiet");
  });

  it("--json beats --quiet when both given", () => {
    const s = resolveSettings({ json: true, quiet: true }, {}, {});
    expect(s.output).toBe("json");
  });

  it("strips trailing slash from server", () => {
    const s = resolveSettings({ server: "https://x.example/" }, {}, {});
    expect(s.server).toBe("https://x.example");
  });

  it("rejects invalid server URLs", () => {
    expect(() => resolveSettings({ server: "nope" }, {}, {})).toThrow(/url/i);
    expect(() => resolveSettings({}, { DEADROP_SERVER: "ftp://x" }, {})).toThrow(/url/i);
  });

  it("rejects invalid TTL from env", () => {
    expect(() => resolveSettings({}, { DEADROP_TTL: "soon" }, {})).toThrow(/invalid ttl/i);
  });
});
