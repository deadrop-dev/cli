import { bytesToBase64Url, base64UrlToBytes } from "@deadrop/crypto";

/**
 * File-mode envelope (SPEC §10 draft) — a file is a plaintext JSON envelope
 * encrypted exactly like a text secret. The server never learns it's a file:
 * detection happens client-side on the decrypted text only.
 *
 * Canonical form (exactly this key order, compact JSON, data base64url):
 *   {"dd":"file/v1","name":"...","type":"...","data":"..."}
 *
 * The web client implements the identical canonical form; the cross-impl
 * fixture in test/unit/file-envelope.test.ts is character-identical to the
 * one in the web suite.
 */

export const FILE_ENVELOPE_SENTINEL = '{"dd":"file/v1"';

/** Free-tier raw file cap: 256 KiB (matches the web client). */
export const MAX_FILE_BYTES = 262_144;

const MAX_NAME_CHARS = 180;

export interface DecodedFile {
  name: string;
  type: string;
  bytes: Uint8Array;
}

export function encodeFileEnvelope(
  name: string,
  type: string,
  bytes: Uint8Array,
): string {
  return JSON.stringify({
    dd: "file/v1",
    name,
    type,
    data: bytesToBase64Url(bytes),
  });
}

/** Returns the decoded file, or null when the content is not a file envelope. */
export function decodeFileEnvelope(content: string): DecodedFile | null {
  if (!content.startsWith(FILE_ENVELOPE_SENTINEL)) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;
  const o = parsed as Record<string, unknown>;
  if (o.dd !== "file/v1") return null;
  if (typeof o.name !== "string" || typeof o.data !== "string") return null;
  const type = typeof o.type === "string" ? o.type : "";
  if (!/^[A-Za-z0-9_-]*$/.test(o.data)) return null;
  try {
    return { name: o.name, type, bytes: base64UrlToBytes(o.data) };
  } catch {
    return null;
  }
}

/**
 * Filename safety is the recipient's duty: the envelope's name field is
 * attacker-controlled. Strips path separators and control characters so a
 * written file can never escape the target directory.
 */
export function sanitizeFilename(name: string): string {
  const cleaned = name
    .replace(/[\\/:*?"<>|]/g, "_")
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim();
  const capped = cleaned.slice(0, MAX_NAME_CHARS).trim();
  if (capped === "" || /^\.+$/.test(capped)) return "download.bin";
  // Leading dots are deliberately kept: ".env" is a core filename here.
  // Traversal is already impossible (separators stripped above).
  return capped;
}

export function humanFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/** Display-only mime hint by extension — never trusted on the receive side. */
const MIME_BY_EXT: Record<string, string> = {
  ".txt": "text/plain",
  ".md": "text/markdown",
  ".env": "text/plain",
  ".json": "application/json",
  ".yaml": "text/yaml",
  ".yml": "text/yaml",
  ".csv": "text/csv",
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".zip": "application/zip",
  ".pem": "application/x-pem-file",
};

export function mimeFromName(name: string): string {
  const dot = name.lastIndexOf(".");
  if (dot < 0) return "";
  return MIME_BY_EXT[name.slice(dot).toLowerCase()] ?? "";
}
