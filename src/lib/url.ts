import { userError } from "./errors.js";

/** KDF selector per SPEC v2.0 §4. "a2." (Argon2id) is reserved, not implemented. */
export type Kdf = "none" | "pbkdf2";

export interface ParsedSecretUrl {
  /** Origin only, e.g. "https://deadrop.dev" */
  server: string;
  /** 32-char base64url id */
  id: string;
  /** 43-char base64url URL key (NOT the derived key for password secrets) */
  key: string;
  kdf: Kdf;
}

const ID_RE = /^[A-Za-z0-9_-]{32}$/;
const KEY_RE = /^[A-Za-z0-9_-]{43}$/;

/**
 * Parse a Deadrop secret URL: {server}/s/{id}#{key} or {server}/s/{id}#p.{key}.
 * Unknown fragment prefixes are refused — never guess a KDF (SPEC §4).
 */
export function parseSecretUrl(input: string): ParsedSecretUrl {
  let u: URL;
  try {
    u = new URL(input.trim());
  } catch {
    throw userError(`Not a valid URL: "${input}"`);
  }

  const pathMatch = /^\/s\/([^/]+)$/.exec(u.pathname);
  if (!pathMatch) {
    throw userError(
      `Not a Deadrop secret URL (expected {server}/s/{id}#{key}): "${input}"`,
    );
  }
  const id = pathMatch[1]!;
  if (!ID_RE.test(id)) {
    throw userError(`Invalid secret id in URL (expected 32 base64url chars): "${id}"`);
  }

  const fragment = u.hash.startsWith("#") ? u.hash.slice(1) : u.hash;
  if (!fragment) {
    throw userError(
      "URL has no #fragment — the decryption key is missing. Copy the full link.",
    );
  }

  let kdf: Kdf;
  let key: string;
  const dot = fragment.indexOf(".");
  if (dot === -1) {
    kdf = "none";
    key = fragment;
  } else {
    const prefix = fragment.slice(0, dot);
    key = fragment.slice(dot + 1);
    if (prefix === "p") {
      kdf = "pbkdf2";
    } else {
      throw userError(
        `Unsupported KDF selector "${prefix}." in URL fragment. ` +
          "This link may have been created by a newer Deadrop client — update the CLI.",
      );
    }
  }

  if (!KEY_RE.test(key)) {
    throw userError("Invalid key in URL fragment (expected 43 base64url chars).");
  }

  return { server: u.origin, id, key, kdf };
}

/** Build a Deadrop secret URL. `password` selects the `p.` KDF prefix. */
export function buildSecretUrl(
  server: string,
  id: string,
  key: string,
  password: boolean,
): string {
  const base = server.replace(/\/+$/, "");
  return `${base}/s/${id}#${password ? "p." : ""}${key}`;
}
