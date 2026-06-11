import { describe, it, expect } from "vitest";
import { parseTtl, ttlToHuman, MAX_TTL_MINUTES } from "../../src/lib/ttl.js";

describe("parseTtl", () => {
  it("parses minutes", () => {
    expect(parseTtl("5m")).toBe(5);
    expect(parseTtl("1m")).toBe(1);
    expect(parseTtl("90m")).toBe(90);
  });

  it("parses hours", () => {
    expect(parseTtl("1h")).toBe(60);
    expect(parseTtl("24h")).toBe(1440);
  });

  it("parses days", () => {
    expect(parseTtl("1d")).toBe(1440);
    expect(parseTtl("7d")).toBe(10080);
  });

  it("is case-insensitive and trims whitespace", () => {
    expect(parseTtl(" 5M ")).toBe(5);
    expect(parseTtl("1H")).toBe(60);
  });

  it("accepts bare integers as minutes", () => {
    expect(parseTtl("30")).toBe(30);
  });

  it("rejects zero, negative, and fractional values", () => {
    expect(() => parseTtl("0m")).toThrow(/invalid ttl/i);
    expect(() => parseTtl("-5m")).toThrow(/invalid ttl/i);
    expect(() => parseTtl("1.5h")).toThrow(/invalid ttl/i);
  });

  it("rejects values above 7 days", () => {
    expect(() => parseTtl("8d")).toThrow(/7 days/i);
    expect(() => parseTtl("10081m")).toThrow(/7 days/i);
    expect(parseTtl("10080m")).toBe(MAX_TTL_MINUTES);
  });

  it("rejects garbage", () => {
    expect(() => parseTtl("")).toThrow(/invalid ttl/i);
    expect(() => parseTtl("soon")).toThrow(/invalid ttl/i);
    expect(() => parseTtl("5x")).toThrow(/invalid ttl/i);
    expect(() => parseTtl("h")).toThrow(/invalid ttl/i);
  });
});

describe("ttlToHuman", () => {
  it("renders human-friendly durations", () => {
    expect(ttlToHuman(5)).toBe("5 minutes");
    expect(ttlToHuman(1)).toBe("1 minute");
    expect(ttlToHuman(60)).toBe("1 hour");
    expect(ttlToHuman(120)).toBe("2 hours");
    expect(ttlToHuman(90)).toBe("1 hour 30 minutes");
    expect(ttlToHuman(1440)).toBe("1 day");
    expect(ttlToHuman(10080)).toBe("7 days");
  });
});
