import { userError } from "./errors.js";

/**
 * Request-flow URLs (SPEC 2.1 §9.2):
 *   request link  {server}/r/{id}            — safe to send, no key material
 *   claim link    {server}/r/{id}/claim#{key} — private key in fragment ONLY
 */

export interface ParsedRequestUrl {
  /** Origin only, e.g. "https://deadrop.dev" */
  server: string;
  /** 32-char base64url id */
  id: string;
}

export interface ParsedClaimUrl extends ParsedRequestUrl {
  /** base64url PKCS8 ECDH private key from the fragment */
  privateKey: string;
}

const ID_RE = /^[A-Za-z0-9_-]{32}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;

/** Parse {server}/r/{id} — the link the requester sends out. */
export function parseRequestUrl(input: string): ParsedRequestUrl {
  let u: URL;
  try {
    u = new URL(input.trim());
  } catch {
    throw userError(`Not a valid URL: "${input}"`);
  }
  const m = /^\/r\/([^/]+)$/.exec(u.pathname);
  if (!m) {
    throw userError(`Not a Deadrop request URL (expected {server}/r/{id}): "${input}"`);
  }
  const id = m[1]!;
  if (!ID_RE.test(id)) {
    throw userError(`Invalid request id in URL (expected 32 base64url chars): "${id}"`);
  }
  return { server: u.origin, id };
}

/** Parse {server}/r/{id}/claim#{privateKey} — the link the requester keeps. */
export function parseClaimUrl(input: string): ParsedClaimUrl {
  let u: URL;
  try {
    u = new URL(input.trim());
  } catch {
    throw userError(`Not a valid URL: "${input}"`);
  }
  const m = /^\/r\/([^/]+)\/claim$/.exec(u.pathname);
  if (!m) {
    throw userError(
      `Not a Deadrop claim URL (expected {server}/r/{id}/claim#{key}): "${input}"`,
    );
  }
  const id = m[1]!;
  if (!ID_RE.test(id)) {
    throw userError(`Invalid request id in URL (expected 32 base64url chars): "${id}"`);
  }
  const fragment = u.hash.startsWith("#") ? u.hash.slice(1) : u.hash;
  if (!fragment) {
    throw userError(
      "URL has no #fragment — the claim key is missing. Copy the full claim link.",
    );
  }
  if (!B64URL_RE.test(fragment)) {
    throw userError("Invalid claim key in URL fragment (expected base64url).");
  }
  return { server: u.origin, id, privateKey: fragment };
}

export function buildRequestUrl(server: string, id: string): string {
  return `${server.replace(/\/+$/, "")}/r/${id}`;
}

export function buildClaimUrl(server: string, id: string, privateKey: string): string {
  return `${server.replace(/\/+$/, "")}/r/${id}/claim#${privateKey}`;
}
