import { CliError, serverError, userError } from "./errors.js";

/** POST /api/secrets body — exact SPEC v2.0 wire field names. */
export interface CreatePayload {
  id: string;
  encrypted: string;
  iv: string;
  keyHash: string;
  expiresMinutes: number;
  hint?: string;
}

export interface RetrievedSecret {
  encrypted: string;
  iv: string;
  hint: string | null;
}

export interface SecretMeta {
  hint: string | null;
}

/** 409 on create: client-generated id collided — regenerate and retry once. */
export class IdCollisionError extends Error {
  constructor() {
    super("Secret id collision (409) — regenerate the id and retry.");
    this.name = "IdCollisionError";
  }
}

async function doFetch(url: string, init: RequestInit): Promise<Response> {
  try {
    return await fetch(url, init);
  } catch (e) {
    const cause = e instanceof Error ? e.message : String(e);
    throw serverError(`Could not reach server: ${cause}`);
  }
}

function mapError(status: number, action: "create" | "retrieve" | "revoke"): CliError {
  if (status === 403) {
    return new CliError(
      action === "revoke"
        ? "Server rejected the key — wrong URL key or password. The secret was NOT revoked."
        : "Server rejected the key — wrong URL key or password. The secret was NOT burned; you can retry.",
      1,
      "wrong-key",
    );
  }
  if (status === 404) {
    return new CliError(
      "Secret not found — it was already opened (burned), expired, revoked, or never existed.",
      1,
      "gone",
    );
  }
  if (status === 429) {
    return new CliError("Rate limited by the server (429). Wait a minute and retry.", 2, "rate-limited");
  }
  if (status >= 500) {
    return serverError(`Server error (${status}). Try again later.`);
  }
  return userError(`Request rejected by server (${status}).`);
}

/** POST /api/secrets. Throws IdCollisionError on 409. */
export async function createSecret(server: string, payload: CreatePayload): Promise<void> {
  const res = await doFetch(`${server}/api/secrets`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (res.ok) return;
  if (res.status === 409) throw new IdCollisionError();
  throw mapError(res.status, "create");
}

/** GET /api/secrets/{id}?k={keyHash} — burns on success. */
export async function retrieveSecret(
  server: string,
  id: string,
  keyHash: string,
): Promise<RetrievedSecret> {
  const res = await doFetch(
    `${server}/api/secrets/${id}?k=${encodeURIComponent(keyHash)}`,
    { method: "GET" },
  );
  if (!res.ok) throw mapError(res.status, "retrieve");
  const body = (await res.json()) as Partial<RetrievedSecret>;
  if (typeof body.encrypted !== "string" || typeof body.iv !== "string") {
    throw serverError("Malformed server response (missing encrypted/iv).");
  }
  return { encrypted: body.encrypted, iv: body.iv, hint: body.hint ?? null };
}

/** GET /api/secrets/{id}/meta — hint without key proof (semi-public). */
export async function getMeta(server: string, id: string): Promise<SecretMeta> {
  const res = await doFetch(`${server}/api/secrets/${id}/meta`, { method: "GET" });
  if (!res.ok) throw mapError(res.status, "retrieve");
  const body = (await res.json()) as Partial<SecretMeta>;
  return { hint: body.hint ?? null };
}

/** DELETE /api/secrets/{id}?k={keyHash} — same key proof as retrieval. */
export async function revokeSecret(
  server: string,
  id: string,
  keyHash: string,
): Promise<void> {
  const res = await doFetch(
    `${server}/api/secrets/${id}?k=${encodeURIComponent(keyHash)}`,
    { method: "DELETE" },
  );
  if (!res.ok) throw mapError(res.status, "revoke");
}

// ---------------------------------------------------------------------------
// Request flow (SPEC 2.1 §9) — exact wire field names throughout.
// ---------------------------------------------------------------------------

/** POST /api/requests body. */
export interface CreateRequestPayload {
  id: string;
  publicKey: string;
  claimProof: string;
  expiresMinutes: number;
  prompt?: string;
}

/** GET /api/requests/{id} — semi-public status for the responder. */
export interface RequestStatus {
  publicKey: string;
  prompt: string;
  fulfilled: boolean;
}

/** POST /api/requests/{id}/response body. */
export interface FulfillPayload {
  encrypted: string;
  iv: string;
  wrappedKey: string;
  wrapIv: string;
  hkdfSalt: string;
  responderPublicKey: string;
}

/** GET /api/requests/{id}/response — 202 means pending, nothing burned. */
export type ClaimResult =
  | { status: "pending" }
  | { status: "claimed"; blob: FulfillPayload };

/** 409 on fulfill: the request already has its one response. */
export class AlreadyFulfilledError extends Error {
  constructor() {
    super("This request was already answered — each request takes exactly one response.");
    this.name = "AlreadyFulfilledError";
  }
}

const REQUEST_GONE =
  "Request not found — it expired, was already claimed, or never existed.";

/** POST /api/requests. Throws IdCollisionError on 409. */
export async function createRequest(
  server: string,
  payload: CreateRequestPayload,
): Promise<void> {
  const res = await doFetch(`${server}/api/requests`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (res.ok) return;
  if (res.status === 409) throw new IdCollisionError();
  throw mapError(res.status, "create");
}

/** GET /api/requests/{id} — no key proof needed (semi-public, like /meta). */
export async function getRequestStatus(
  server: string,
  id: string,
): Promise<RequestStatus> {
  const res = await doFetch(`${server}/api/requests/${id}`, { method: "GET" });
  if (res.status === 404) throw new CliError(REQUEST_GONE, 1, "gone");
  if (!res.ok) throw mapError(res.status, "retrieve");
  const body = (await res.json()) as Partial<RequestStatus>;
  if (typeof body.publicKey !== "string") {
    throw serverError("Malformed server response (missing publicKey).");
  }
  return {
    publicKey: body.publicKey,
    prompt: body.prompt ?? "",
    fulfilled: Boolean(body.fulfilled),
  };
}

/** POST /api/requests/{id}/response. Throws AlreadyFulfilledError on 409. */
export async function fulfillRequest(
  server: string,
  id: string,
  payload: FulfillPayload,
): Promise<void> {
  const res = await doFetch(`${server}/api/requests/${id}/response`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (res.ok) return;
  if (res.status === 409) throw new AlreadyFulfilledError();
  if (res.status === 404) throw new CliError(REQUEST_GONE, 1, "gone");
  throw mapError(res.status, "create");
}

/**
 * GET /api/requests/{id}/response?proof={claimProof}.
 * §9.3 precedence: 404 gone → 403 proof mismatch (no burn) → 202 pending
 * (no burn) → 200 burn. 202 is a normal outcome, not an error.
 */
export async function claimResponse(
  server: string,
  id: string,
  claimProof: string,
): Promise<ClaimResult> {
  const res = await doFetch(
    `${server}/api/requests/${id}/response?proof=${encodeURIComponent(claimProof)}`,
    { method: "GET" },
  );
  if (res.status === 202) return { status: "pending" };
  if (res.status === 404) throw new CliError(REQUEST_GONE, 1, "gone");
  if (res.status === 403) {
    throw new CliError(
      "Server rejected the claim proof — the claim link looks corrupted. Nothing was burned.",
      1,
      "wrong-key",
    );
  }
  if (!res.ok) throw mapError(res.status, "retrieve");
  const body = (await res.json()) as Partial<FulfillPayload>;
  for (const field of [
    "encrypted",
    "iv",
    "wrappedKey",
    "wrapIv",
    "hkdfSalt",
    "responderPublicKey",
  ] as const) {
    if (typeof body[field] !== "string") {
      throw serverError(`Malformed server response (missing ${field}).`);
    }
  }
  return { status: "claimed", blob: body as FulfillPayload };
}
