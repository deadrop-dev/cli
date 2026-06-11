import { describe, it, expect } from "vitest";
import { parseSecretUrl, buildSecretUrl } from "../../src/lib/url.js";

const ID = "abcDEF0123456789abcDEF0123456789"; // 32 base64url chars
const KEY = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 base64url chars

describe("parseSecretUrl", () => {
  it("parses a plain (no password) URL", () => {
    const r = parseSecretUrl(`https://deadrop.dev/s/${ID}#${KEY}`);
    expect(r).toEqual({
      server: "https://deadrop.dev",
      id: ID,
      key: KEY,
      kdf: "none",
    });
  });

  it("parses a password-protected URL (p. prefix)", () => {
    const r = parseSecretUrl(`https://deadrop.dev/s/${ID}#p.${KEY}`);
    expect(r.kdf).toBe("pbkdf2");
    expect(r.key).toBe(KEY);
  });

  it("preserves non-default server origin including port", () => {
    const r = parseSecretUrl(`http://localhost:8787/s/${ID}#${KEY}`);
    expect(r.server).toBe("http://localhost:8787");
  });

  it("refuses unknown KDF selector prefixes (never guess)", () => {
    expect(() => parseSecretUrl(`https://deadrop.dev/s/${ID}#a2.${KEY}`)).toThrow(
      /unsupported|unknown/i,
    );
    expect(() => parseSecretUrl(`https://deadrop.dev/s/${ID}#zz.${KEY}`)).toThrow(
      /unsupported|unknown/i,
    );
  });

  it("rejects URLs without a fragment", () => {
    expect(() => parseSecretUrl(`https://deadrop.dev/s/${ID}`)).toThrow(/fragment|key/i);
  });

  it("rejects malformed ids and keys", () => {
    expect(() => parseSecretUrl(`https://deadrop.dev/s/short#${KEY}`)).toThrow(/id/i);
    expect(() => parseSecretUrl(`https://deadrop.dev/s/${ID}#tooshort`)).toThrow(/key/i);
    expect(() => parseSecretUrl(`https://deadrop.dev/s/${ID}#p.tooshort`)).toThrow(/key/i);
  });

  it("rejects non-deadrop paths and non-URLs", () => {
    expect(() => parseSecretUrl("not a url")).toThrow(/url/i);
    expect(() => parseSecretUrl(`https://deadrop.dev/x/${ID}#${KEY}`)).toThrow(/url/i);
  });
});

describe("buildSecretUrl", () => {
  it("builds plain URLs", () => {
    expect(buildSecretUrl("https://deadrop.dev", ID, KEY, false)).toBe(
      `https://deadrop.dev/s/${ID}#${KEY}`,
    );
  });

  it("builds password URLs with p. prefix", () => {
    expect(buildSecretUrl("https://deadrop.dev", ID, KEY, true)).toBe(
      `https://deadrop.dev/s/${ID}#p.${KEY}`,
    );
  });

  it("strips trailing slash from server", () => {
    expect(buildSecretUrl("https://deadrop.dev/", ID, KEY, false)).toBe(
      `https://deadrop.dev/s/${ID}#${KEY}`,
    );
  });

  it("round-trips through parseSecretUrl", () => {
    const url = buildSecretUrl("http://127.0.0.1:9999", ID, KEY, true);
    const r = parseSecretUrl(url);
    expect(r).toEqual({ server: "http://127.0.0.1:9999", id: ID, key: KEY, kdf: "pbkdf2" });
  });
});
