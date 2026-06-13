import { describe, it, expect } from "vitest";
import {
  encodeFileEnvelope,
  decodeFileEnvelope,
  sanitizeFilename,
  humanFileSize,
  mimeFromName,
  MAX_FILE_BYTES,
  FILE_ENVELOPE_SENTINEL,
} from "../../src/lib/file-envelope.js";

// Cross-implementation fixture — the web client's suite asserts the exact
// same literal (frontend/src/lib/fileEnvelope.test.ts). If either side
// changes the canonical form, both suites fail.
const FIXTURE_BYTES = new Uint8Array(64).map((_, i) => i);
const FIXTURE_ENVELOPE =
  '{"dd":"file/v1","name":"report final.pdf","type":"application/pdf","data":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw"}';

describe("file envelope (canonical form)", () => {
  it("produces the cross-impl fixture string character-identically", () => {
    expect(
      encodeFileEnvelope("report final.pdf", "application/pdf", FIXTURE_BYTES),
    ).toBe(FIXTURE_ENVELOPE);
  });

  it("starts with the sentinel", () => {
    expect(encodeFileEnvelope("a", "", new Uint8Array([1])).startsWith(FILE_ENVELOPE_SENTINEL)).toBe(true);
  });

  it("round-trips arbitrary binary", () => {
    const bytes = new Uint8Array(300).map((_, i) => (i * 31) & 0xff);
    const d = decodeFileEnvelope(encodeFileEnvelope("x.bin", "", bytes));
    expect(Array.from(d!.bytes)).toEqual(Array.from(bytes));
  });

  it("decodes the fixture", () => {
    const d = decodeFileEnvelope(FIXTURE_ENVELOPE);
    expect(d?.name).toBe("report final.pdf");
    expect(d?.type).toBe("application/pdf");
    expect(Array.from(d!.bytes)).toEqual(Array.from(FIXTURE_BYTES));
  });

  it("rejects non-envelopes", () => {
    expect(decodeFileEnvelope("hunter2")).toBeNull();
    expect(decodeFileEnvelope('{"user":"admin"}')).toBeNull();
    expect(decodeFileEnvelope('{"dd": broken')).toBeNull();
    expect(decodeFileEnvelope('{ "dd": "file/v1", "name": "a", "data": "" }')).toBeNull();
    expect(decodeFileEnvelope('{"dd":"file/v1","name":"a","data":"<bad>"}')).toBeNull();
    expect(decodeFileEnvelope('{"dd":"file/v1","data":"AA"}')).toBeNull();
  });
});

describe("sanitizeFilename", () => {
  it("strips path separators and control chars", () => {
    expect(sanitizeFilename("../../etc/passwd")).toBe(".._.._etc_passwd");
    expect(sanitizeFilename("..\\..\\evil.exe")).toBe(".._.._evil.exe");
  });

  it("keeps dotfile names like .env (core use case)", () => {
    expect(sanitizeFilename(".env")).toBe(".env");
    expect(sanitizeFilename(".env.production")).toBe(".env.production");
  });

  it("falls back for empty / dot-only names", () => {
    expect(sanitizeFilename("")).toBe("download.bin");
    expect(sanitizeFilename("..")).toBe("download.bin");
  });
});

describe("helpers", () => {
  it("humanFileSize", () => {
    expect(humanFileSize(64)).toBe("64 B");
    expect(humanFileSize(MAX_FILE_BYTES)).toBe("256.0 KB");
  });

  it("mimeFromName", () => {
    expect(mimeFromName("a.pdf")).toBe("application/pdf");
    expect(mimeFromName(".env")).toBe("text/plain");
    expect(mimeFromName("noext")).toBe("");
    expect(mimeFromName("weird.xyz")).toBe("");
  });
});
