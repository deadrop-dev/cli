import { describe, it, expect } from "vitest";
import {
  buildClaimUrl,
  buildRequestUrl,
  parseClaimUrl,
  parseRequestUrl,
} from "../../src/lib/request-url.js";
import { CliError } from "../../src/lib/errors.js";

const ID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const KEY = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQ";

describe("parseRequestUrl", () => {
  it("parses a request link", () => {
    const p = parseRequestUrl(`https://deadrop.dev/r/${ID}`);
    expect(p).toEqual({ server: "https://deadrop.dev", id: ID });
  });

  it("rejects a claim link (wrong path shape)", () => {
    expect(() => parseRequestUrl(`https://deadrop.dev/r/${ID}/claim#${KEY}`)).toThrow(CliError);
  });

  it("rejects a secret link", () => {
    expect(() => parseRequestUrl(`https://deadrop.dev/s/${ID}#${KEY}`)).toThrow(CliError);
  });

  it("rejects a malformed id", () => {
    expect(() => parseRequestUrl("https://deadrop.dev/r/short")).toThrow(/Invalid request id/);
  });
});

describe("parseClaimUrl", () => {
  it("parses a claim link with the key in the fragment", () => {
    const p = parseClaimUrl(`https://deadrop.dev/r/${ID}/claim#${KEY}`);
    expect(p).toEqual({ server: "https://deadrop.dev", id: ID, privateKey: KEY });
  });

  it("rejects a claim link without a fragment", () => {
    expect(() => parseClaimUrl(`https://deadrop.dev/r/${ID}/claim`)).toThrow(/claim key is missing/);
  });

  it("rejects non-base64url fragments", () => {
    expect(() => parseClaimUrl(`https://deadrop.dev/r/${ID}/claim#not+valid/b64`)).toThrow(
      /Invalid claim key/,
    );
  });

  it("rejects a plain request link", () => {
    expect(() => parseClaimUrl(`https://deadrop.dev/r/${ID}`)).toThrow(CliError);
  });
});

describe("build round-trips", () => {
  it("request url round-trips through parse", () => {
    const url = buildRequestUrl("https://deadrop.dev/", ID);
    expect(url).toBe(`https://deadrop.dev/r/${ID}`);
    expect(parseRequestUrl(url).id).toBe(ID);
  });

  it("claim url round-trips through parse", () => {
    const url = buildClaimUrl("https://deadrop.dev", ID, KEY);
    expect(parseClaimUrl(url)).toEqual({ server: "https://deadrop.dev", id: ID, privateKey: KEY });
  });
});
