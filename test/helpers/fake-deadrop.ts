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

export interface FakeDeadrop {
  store: Map<string, StoredSecret>;
  /** number of upcoming POSTs to reject with 409 (collision simulation) */
  collideNext: number;
}

/**
 * Minimal SPEC v2.0-conformant in-memory Deadrop server behavior, attached
 * to a MockServer. Burn-on-read, 403 without burn on key mismatch, 404 when
 * gone, /meta without key proof, DELETE with same key proof.
 */
export function installFakeDeadrop(srv: MockServer): FakeDeadrop {
  const fake: FakeDeadrop = { store: new Map(), collideNext: 0 };

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

    return json(res, 404, { error: "no route" });
  });

  return fake;
}
