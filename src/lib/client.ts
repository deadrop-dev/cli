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
    return userError(
      action === "revoke"
        ? "Server rejected the key — wrong URL key or password. The secret was NOT revoked."
        : "Server rejected the key — wrong URL key or password. The secret was NOT burned; you can retry.",
    );
  }
  if (status === 404) {
    return userError(
      "Secret not found — it was already opened (burned), expired, revoked, or never existed.",
    );
  }
  if (status === 429) {
    return serverError("Rate limited by the server (429). Wait a minute and retry.");
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
