import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { startMockServer, json, type MockServer } from "../helpers/mock-server.js";
import {
  createSecret,
  retrieveSecret,
  getMeta,
  revokeSecret,
  IdCollisionError,
} from "../../src/lib/client.js";
import { CliError } from "../../src/lib/errors.js";

let srv: MockServer;
beforeAll(async () => {
  srv = await startMockServer();
});
afterAll(async () => {
  await srv.close();
});
beforeEach(() => {
  srv.requests.length = 0;
});

const PAYLOAD = {
  id: "abcDEF0123456789abcDEF0123456789",
  encrypted: "ZW5jcnlwdGVkLWJsb2I",
  iv: "aXYtYnl0ZXMhIQ",
  keyHash: "AdD6vSUfy74rk7S5J7Jq0q",
  expiresMinutes: 60,
};

describe("createSecret wire format", () => {
  it("POSTs exact SPEC v2.0 field names to /api/secrets", async () => {
    srv.setResponder((_req, res) => json(res, 201, { ok: true }));
    await createSecret(srv.baseUrl, PAYLOAD);

    expect(srv.requests).toHaveLength(1);
    const req = srv.requests[0]!;
    expect(req.method).toBe("POST");
    expect(req.url).toBe("/api/secrets");
    expect(req.headers["content-type"]).toMatch(/^application\/json/);

    const body = JSON.parse(req.body);
    expect(Object.keys(body).sort()).toEqual([
      "encrypted",
      "expiresMinutes",
      "id",
      "iv",
      "keyHash",
    ]);
    expect(body).toEqual(PAYLOAD);
    expect(typeof body.expiresMinutes).toBe("number");
  });

  it("includes hint only when provided", async () => {
    srv.setResponder((_req, res) => json(res, 201, { ok: true }));
    await createSecret(srv.baseUrl, { ...PAYLOAD, hint: "usual dev password" });
    const body = JSON.parse(srv.requests[0]!.body);
    expect(body.hint).toBe("usual dev password");
  });

  it("throws IdCollisionError on 409 so callers can regenerate the id", async () => {
    srv.setResponder((_req, res) => json(res, 409, { error: "conflict" }));
    await expect(createSecret(srv.baseUrl, PAYLOAD)).rejects.toBeInstanceOf(IdCollisionError);
  });

  it("maps 429 to exit code 2 (rate limited)", async () => {
    srv.setResponder((_req, res) => json(res, 429, { error: "rate limited" }));
    const err = await createSecret(srv.baseUrl, PAYLOAD).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.exitCode).toBe(2);
    expect(err.message).toMatch(/rate.?limit/i);
  });

  it("maps 5xx to exit code 2", async () => {
    srv.setResponder((_req, res) => json(res, 503, { error: "down" }));
    const err = await createSecret(srv.baseUrl, PAYLOAD).catch((e) => e);
    expect(err.exitCode).toBe(2);
  });

  it("maps 400 to exit code 1 (user error)", async () => {
    srv.setResponder((_req, res) => json(res, 400, { error: "bad request" }));
    const err = await createSecret(srv.baseUrl, PAYLOAD).catch((e) => e);
    expect(err.exitCode).toBe(1);
  });

  it("maps network failure to exit code 2", async () => {
    const err = await createSecret("http://127.0.0.1:1", PAYLOAD).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.exitCode).toBe(2);
  });
});

describe("retrieveSecret wire format", () => {
  it("GETs /api/secrets/{id} with key hash in query param k", async () => {
    srv.setResponder((_req, res) =>
      json(res, 200, { encrypted: "blob", iv: "iv", hint: null }),
    );
    const out = await retrieveSecret(srv.baseUrl, PAYLOAD.id, PAYLOAD.keyHash);
    const req = srv.requests[0]!;
    expect(req.method).toBe("GET");
    expect(req.url).toBe(`/api/secrets/${PAYLOAD.id}?k=${PAYLOAD.keyHash}`);
    expect(out).toEqual({ encrypted: "blob", iv: "iv", hint: null });
  });

  it("maps 403 to wrong-key user error (exit 1)", async () => {
    srv.setResponder((_req, res) => json(res, 403, { error: "forbidden" }));
    const err = await retrieveSecret(srv.baseUrl, PAYLOAD.id, PAYLOAD.keyHash).catch((e) => e);
    expect(err.exitCode).toBe(1);
    expect(err.message).toMatch(/key|password/i);
  });

  it("maps 404 to gone user error (exit 1)", async () => {
    srv.setResponder((_req, res) => json(res, 404, { error: "not found" }));
    const err = await retrieveSecret(srv.baseUrl, PAYLOAD.id, PAYLOAD.keyHash).catch((e) => e);
    expect(err.exitCode).toBe(1);
    expect(err.message).toMatch(/burned|expired|revoked|not exist|gone/i);
  });
});

describe("getMeta wire format", () => {
  it("GETs /api/secrets/{id}/meta without key proof", async () => {
    srv.setResponder((_req, res) => json(res, 200, { hint: "a hint" }));
    const out = await getMeta(srv.baseUrl, PAYLOAD.id);
    const req = srv.requests[0]!;
    expect(req.method).toBe("GET");
    expect(req.url).toBe(`/api/secrets/${PAYLOAD.id}/meta`);
    expect(out).toEqual({ hint: "a hint" });
  });
});

describe("revokeSecret wire format", () => {
  it("DELETEs /api/secrets/{id} with key hash in query param k", async () => {
    srv.setResponder((_req, res) => {
      res.writeHead(204);
      res.end();
    });
    await revokeSecret(srv.baseUrl, PAYLOAD.id, PAYLOAD.keyHash);
    const req = srv.requests[0]!;
    expect(req.method).toBe("DELETE");
    expect(req.url).toBe(`/api/secrets/${PAYLOAD.id}?k=${PAYLOAD.keyHash}`);
  });

  it("maps 404 on revoke to user error", async () => {
    srv.setResponder((_req, res) => json(res, 404, { error: "not found" }));
    const err = await revokeSecret(srv.baseUrl, PAYLOAD.id, PAYLOAD.keyHash).catch((e) => e);
    expect(err.exitCode).toBe(1);
  });
});
