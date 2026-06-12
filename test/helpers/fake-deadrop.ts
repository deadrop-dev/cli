import type { MockServer, RecordedRequest } from "./mock-server.js";
import { json } from "./mock-server.js";
import type { ServerResponse } from "node:http";

interface StoredSecret {
  keyHash: string;
  encrypted: string;
  iv: string;
  hint: string | null;
  expiresMinutes: number;
}

interface StoredResponse {
  encrypted: string;
  iv: string;
  wrappedKey: string;
  wrapIv: string;
  hkdfSalt: string;
  responderPublicKey: string;
}

interface StoredRequest {
  publicKey: string;
  claimProof: string;
  prompt: string;
  fulfilled: boolean;
  response: StoredResponse | null;
  expiresMinutes: number;
}

export interface FakeDeadrop {
  store: Map<string, StoredSecret>;
  requests: Map<string, StoredRequest>;
  /** number of upcoming POSTs to reject with 409 (collision simulation) */
  collideNext: number;
}

/**
 * Minimal SPEC-conformant in-memory Deadrop server behavior, attached to a
 * MockServer. Secrets (v2.0): burn-on-read, 403 without burn on key mismatch,
 * 404 when gone, /meta without key proof, DELETE with same key proof.
 * Requests (2.1 §9): one response per request (409), claim precedence
 * 404 → 403 (no burn) → 202 (no burn) → 200 (whole-record burn).
 */
export function installFakeDeadrop(srv: MockServer): FakeDeadrop {
  const fake: FakeDeadrop = { store: new Map(), requests: new Map(), collideNext: 0 };

  srv.setResponder((req: RecordedRequest, res: ServerResponse) => {
    const m = req.method;
    const u = new URL(req.url, "http://x");

    if (m === "POST" && u.pathname === "/api/secrets") {
      const body = JSON.parse(req.body);
      if (fake.collideNext > 0) {
        fake.collideNext -= 1;
        return json(res, 409, { error: "conflict" });
      }
      if (fake.store.has(body.id)) return json(res, 409, { error: "conflict" });
      fake.store.set(body.id, {
        keyHash: body.keyHash,
        encrypted: body.encrypted,
        iv: body.iv,
        hint: body.hint ?? null,
        expiresMinutes: body.expiresMinutes,
      });
      return json(res, 201, { ok: true });
    }

    const metaMatch = /^\/api\/secrets\/([^/]+)\/meta$/.exec(u.pathname);
    if (m === "GET" && metaMatch) {
      const s = fake.store.get(metaMatch[1]!);
      if (!s) return json(res, 404, { error: "not found" });
      return json(res, 200, { hint: s.hint });
    }

    const idMatch = /^\/api\/secrets\/([^/]+)$/.exec(u.pathname);
    if (idMatch) {
      const id = idMatch[1]!;
      const k = u.searchParams.get("k");
      const s = fake.store.get(id);
      if (!s) return json(res, 404, { error: "not found" });
      if (k !== s.keyHash) return json(res, 403, { error: "forbidden" }); // no burn
      if (m === "GET") {
        fake.store.delete(id); // atomic burn
        return json(res, 200, { encrypted: s.encrypted, iv: s.iv, hint: s.hint });
      }
      if (m === "DELETE") {
        fake.store.delete(id);
        res.writeHead(204);
        return res.end();
      }
    }

    if (m === "POST" && u.pathname === "/api/requests") {
      const body = JSON.parse(req.body);
      if (fake.collideNext > 0) {
        fake.collideNext -= 1;
        return json(res, 409, { error: "conflict" });
      }
      if (fake.requests.has(body.id)) return json(res, 409, { error: "conflict" });
      fake.requests.set(body.id, {
        publicKey: body.publicKey,
        claimProof: body.claimProof,
        prompt: body.prompt ?? "",
        fulfilled: false,
        response: null,
        expiresMinutes: body.expiresMinutes,
      });
      return json(res, 201, { ok: true });
    }

    const respMatch = /^\/api\/requests\/([^/]+)\/response$/.exec(u.pathname);
    if (respMatch) {
      const r = fake.requests.get(respMatch[1]!);
      if (m === "POST") {
        if (!r) return json(res, 404, { error: "not found" });
        if (r.fulfilled) return json(res, 409, { error: "conflict" }); // one response, original intact
        const body = JSON.parse(req.body);
        r.response = {
          encrypted: body.encrypted,
          iv: body.iv,
          wrappedKey: body.wrappedKey,
          wrapIv: body.wrapIv,
          hkdfSalt: body.hkdfSalt,
          responderPublicKey: body.responderPublicKey,
        };
        r.fulfilled = true;
        return json(res, 201, { ok: true });
      }
      if (m === "GET") {
        // §9.3 precedence: 404 → 403 (no burn) → 202 (no burn) → 200 (burn)
        if (!r) return json(res, 404, { error: "not found" });
        if (u.searchParams.get("proof") !== r.claimProof) {
          return json(res, 403, { error: "forbidden" });
        }
        if (!r.fulfilled) return json(res, 202, { status: "pending" });
        fake.requests.delete(respMatch[1]!); // whole-record burn
        return json(res, 200, r.response);
      }
    }

    const reqMatch = /^\/api\/requests\/([^/]+)$/.exec(u.pathname);
    if (m === "GET" && reqMatch) {
      const r = fake.requests.get(reqMatch[1]!);
      if (!r) return json(res, 404, { error: "not found" });
      return json(res, 200, { publicKey: r.publicKey, prompt: r.prompt, fulfilled: r.fulfilled });
    }

    return json(res, 404, { error: "no route" });
  });

  return fake;
}
