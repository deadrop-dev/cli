import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { startMockServer, type MockServer } from "../helpers/mock-server.js";
import { installFakeDeadrop, type FakeDeadrop } from "../helpers/fake-deadrop.js";
import { makeCtx } from "../helpers/fake-ctx.js";
import { runSend } from "../../src/commands/send.js";
import { runReceive } from "../../src/commands/receive.js";
import { runRevoke } from "../../src/commands/revoke.js";
import { runQr } from "../../src/commands/qr.js";
import { runConfig } from "../../src/commands/config.js";
import { parseSecretUrl } from "../../src/lib/url.js";
import { computeKeyHashFromB64 } from "@deadrop/crypto";
import { CliError } from "../../src/lib/errors.js";

let srv: MockServer;
let fake: FakeDeadrop;

beforeAll(async () => {
  srv = await startMockServer();
});
afterAll(async () => {
  await srv.close();
});
beforeEach(() => {
  fake = installFakeDeadrop(srv);
  srv.requests.length = 0;
});

describe("send → receive round-trip (real crypto, real wire)", () => {
  it("round-trips a plain secret", async () => {
    const s = makeCtx();
    await runSend("hello round trip", { server: srv.baseUrl, quiet: true }, s.ctx);
    const url = s.stdout().trim();
    const parsed = parseSecretUrl(url);
    expect(parsed.server).toBe(srv.baseUrl);
    expect(parsed.kdf).toBe("none");

    // wire: POST body had exact SPEC fields
    const post = srv.requests.find((r) => r.method === "POST")!;
    const body = JSON.parse(post.body);
    expect(Object.keys(body).sort()).toEqual([
      "encrypted",
      "expiresMinutes",
      "id",
      "iv",
      "keyHash",
    ]);
    expect(body.expiresMinutes).toBe(60); // default 1h
    expect(body.id).toBe(parsed.id);
    expect(body.keyHash).toBe(await computeKeyHashFromB64(parsed.key));

    const r = makeCtx();
    await runReceive(url, { quiet: true }, r.ctx);
    expect(r.stdout()).toBe("hello round trip");

    // burned: second receive is a 404 user error
    const r2 = makeCtx();
    const err = await runReceive(url, {}, r2.ctx).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.exitCode).toBe(1);
  });

  it("round-trips a password-protected secret; keyHash on wire is the derived hash", async () => {
    const s = makeCtx();
    await runSend("pw secret", { server: srv.baseUrl, password: "hunter2", quiet: true }, s.ctx);
    const url = s.stdout().trim();
    const parsed = parseSecretUrl(url);
    expect(parsed.kdf).toBe("pbkdf2");

    const post = srv.requests.find((r) => r.method === "POST")!;
    const body = JSON.parse(post.body);
    expect(body.keyHash).not.toBe(await computeKeyHashFromB64(parsed.key));

    const r = makeCtx();
    await runReceive(url, { password: "hunter2", quiet: true }, r.ctx);
    expect(r.stdout()).toBe("pw secret");
  });

  it("password receive prompts interactively (prompt via stderr path) and shows hint", async () => {
    const s = makeCtx();
    await runSend(
      "hinted",
      { server: srv.baseUrl, password: "pw", hint: "usual one", quiet: true },
      s.ctx,
    );
    const url = s.stdout().trim();

    let prompted = false;
    const r = makeCtx({
      promptPassword: async (text: string) => {
        prompted = true;
        expect(text).toMatch(/password/i);
        return "pw";
      },
    });
    await runReceive(url, { quiet: true }, r.ctx);
    expect(prompted).toBe(true);
    expect(r.stdout()).toBe("hinted");
    expect(r.stderr()).toContain("usual one"); // hint shown on stderr, not stdout
  });

  it("wrong password yields exit code 1 and does NOT burn the secret", async () => {
    const s = makeCtx();
    await runSend("keep me", { server: srv.baseUrl, password: "right", quiet: true }, s.ctx);
    const url = s.stdout().trim();

    const bad = makeCtx();
    const err = await runReceive(url, { password: "wrong", quiet: true }, bad.ctx).catch((e) => e);
    expect(err.exitCode).toBe(1);
    expect(fake.store.size).toBe(1); // not burned

    const good = makeCtx();
    await runReceive(url, { password: "right", quiet: true }, good.ctx);
    expect(good.stdout()).toBe("keep me");
  });

  it("reads the secret from stdin when piped", async () => {
    const s = makeCtx({ stdinIsTTY: false });
    s.stdin.end("piped secret\n");
    await runSend(undefined, { server: srv.baseUrl, quiet: true }, s.ctx);
    const url = s.stdout().trim();
    const r = makeCtx();
    await runReceive(url, { quiet: true }, r.ctx);
    expect(r.stdout()).toBe("piped secret\n"); // stdin content preserved verbatim
  });

  it("errors with exit 1 when no secret given and stdin is a TTY", async () => {
    const s = makeCtx({ stdinIsTTY: true });
    const err = await runSend(undefined, { server: srv.baseUrl }, s.ctx).catch((e) => e);
    expect(err.exitCode).toBe(1);
    expect(err.message).toMatch(/no secret/i);
  });

  it("retries exactly once with a fresh id on 409 collision", async () => {
    const s = makeCtx();
    fake.collideNext = 1;
    await runSend("collide", { server: srv.baseUrl, quiet: true }, s.ctx);
    const posts = srv.requests.filter((r) => r.method === "POST");
    expect(posts).toHaveLength(2);
    const id1 = JSON.parse(posts[0]!.body).id;
    const id2 = JSON.parse(posts[1]!.body).id;
    expect(id1).not.toBe(id2);

    // round-trip still works after the retry
    const r = makeCtx();
    await runReceive(s.stdout().trim(), { quiet: true }, r.ctx);
    expect(r.stdout()).toBe("collide");
  });

  it("fails with exit 2 when the id collides twice", async () => {
    const s = makeCtx();
    fake.collideNext = 2;
    const err = await runSend("x", { server: srv.baseUrl, quiet: true }, s.ctx).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.exitCode).toBe(2);
  });

  it("sends custom TTL on the wire in minutes", async () => {
    const s = makeCtx();
    await runSend("ttl test", { server: srv.baseUrl, ttl: "7d", quiet: true }, s.ctx);
    const post = srv.requests.find((r) => r.method === "POST")!;
    expect(JSON.parse(post.body).expiresMinutes).toBe(10080);
  });

  it("rejects --hint without --password", async () => {
    const s = makeCtx();
    const err = await runSend("x", { server: srv.baseUrl, hint: "h" }, s.ctx).catch((e) => e);
    expect(err.exitCode).toBe(1);
    expect(err.message).toMatch(/hint.*password/i);
  });

  it("json output has the plan shape", async () => {
    const s = makeCtx();
    await runSend("json test", { server: srv.baseUrl, json: true }, s.ctx);
    const obj = JSON.parse(s.stdout());
    expect(obj.url).toContain("/s/");
    expect(obj.ttl).toBe(3600);
    expect(obj.password_protected).toBe(false);
    expect(typeof obj.id).toBe("string");
    expect(obj.expires_at).toMatch(/^2026-06-12T11:00:00/); // now + 1h
  });

  it("human send output goes quiet when stdout is piped", async () => {
    const s = makeCtx({ stdoutIsTTY: false });
    await runSend("pipe out", { server: srv.baseUrl }, s.ctx);
    expect(s.stdout().trim()).toMatch(/^https?:\/\/[^\s]+#[^\s]+$/);
  });
});

describe("revoke", () => {
  it("revokes via DELETE with key proof; subsequent receive 404s", async () => {
    const s = makeCtx();
    await runSend("revoke me", { server: srv.baseUrl, quiet: true }, s.ctx);
    const url = s.stdout().trim();

    const rv = makeCtx();
    await runRevoke(url, {}, rv.ctx);
    expect(rv.stdout()).toMatch(/revoked/i);

    const del = srv.requests.find((r) => r.method === "DELETE")!;
    expect(del.url).toMatch(/^\/api\/secrets\/[A-Za-z0-9_-]{32}\?k=[A-Za-z0-9_-]{22}$/);

    const r = makeCtx();
    const err = await runReceive(url, {}, r.ctx).catch((e) => e);
    expect(err.exitCode).toBe(1);
  });

  it("revoking a password-protected secret requires the password", async () => {
    const s = makeCtx();
    await runSend("locked", { server: srv.baseUrl, password: "pw", quiet: true }, s.ctx);
    const url = s.stdout().trim();

    const rv = makeCtx({ promptPassword: async () => "pw" });
    await runRevoke(url, { json: true }, rv.ctx);
    expect(JSON.parse(rv.stdout()).revoked).toBe(true);
    expect(fake.store.size).toBe(0);
  });

  it("rejects a bare id (full URL required)", async () => {
    const rv = makeCtx();
    const err = await runRevoke("abc123", {}, rv.ctx).catch((e) => e);
    expect(err.exitCode).toBe(1);
    expect(err.message).toMatch(/url/i);
  });
});

describe("qr", () => {
  it("renders a QR for a given URL to stdout", async () => {
    const q = makeCtx();
    const url = `${srv.baseUrl}/s/abcDEF0123456789abcDEF0123456789#AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
    await runQr(url, {}, q.ctx);
    expect(q.stdout().length).toBeGreaterThan(100); // block art
  });

  it("falls back to the last sent URL when no arg given", async () => {
    const s = makeCtx();
    await runSend("for qr", { server: srv.baseUrl, quiet: true }, s.ctx);
    const url = s.stdout().trim();

    const q = makeCtx({ configFile: s.ctx.configFile });
    await runQr(undefined, {}, q.ctx);
    expect(q.stdout().length).toBeGreaterThan(100);
  });

  it("errors when no URL and no last-sent state", async () => {
    const q = makeCtx();
    const err = await runQr(undefined, {}, q.ctx).catch((e) => e);
    expect(err.exitCode).toBe(1);
  });

  it("--qr on send renders QR after the link", async () => {
    const s = makeCtx();
    await runSend("qr flag", { server: srv.baseUrl, quiet: true, qr: true }, s.ctx);
    expect(s.stdout().length).toBeGreaterThan(200);
  });
});

describe("config command", () => {
  it("set/get/list/reset lifecycle", async () => {
    const c = makeCtx();
    await runConfig(["set", "server", "https://self.example"], {}, c.ctx);
    await runConfig(["set", "default-ttl", "24h"], {}, c.ctx);

    const g = makeCtx({ configFile: c.ctx.configFile });
    await runConfig(["get", "server"], {}, g.ctx);
    expect(g.stdout().trim()).toBe("https://self.example");

    const l = makeCtx({ configFile: c.ctx.configFile });
    await runConfig(["list"], {}, l.ctx);
    expect(l.stdout()).toContain("server=https://self.example");
    expect(l.stdout()).toContain("default-ttl=24h");

    const r = makeCtx({ configFile: c.ctx.configFile });
    await runConfig(["reset"], {}, r.ctx);
    const l2 = makeCtx({ configFile: c.ctx.configFile });
    await runConfig(["list"], {}, l2.ctx);
    expect(l2.stdout().trim()).toBe("");
  });

  it("config server is used by send (config precedence)", async () => {
    const c = makeCtx();
    await runConfig(["set", "server", srv.baseUrl], {}, c.ctx);
    const s = makeCtx({ configFile: c.ctx.configFile });
    await runSend("via config", { quiet: true }, s.ctx);
    expect(s.stdout()).toContain(srv.baseUrl);
  });

  it("env DEADROP_SERVER overrides config", async () => {
    const c = makeCtx();
    await runConfig(["set", "server", "https://wrong.example"], {}, c.ctx);
    const s = makeCtx({ configFile: c.ctx.configFile, env: { DEADROP_SERVER: srv.baseUrl } });
    await runSend("via env", { quiet: true }, s.ctx);
    expect(s.stdout()).toContain(srv.baseUrl);
  });

  it("rejects unknown subcommands and keys with exit 1", async () => {
    const c = makeCtx();
    const e1 = await runConfig(["frobnicate"], {}, c.ctx).catch((e) => e);
    expect(e1.exitCode).toBe(1);
    const e2 = await runConfig(["set", "bogus", "x"], {}, c.ctx).catch((e) => e);
    expect(e2.exitCode).toBe(1);
  });
});

describe("unknown KDF prefix refusal end-to-end", () => {
  it("receive refuses a2. links without contacting the server", async () => {
    const r = makeCtx();
    const url = `${srv.baseUrl}/s/abcDEF0123456789abcDEF0123456789#a2.AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
    const err = await runReceive(url, {}, r.ctx).catch((e) => e);
    expect(err.exitCode).toBe(1);
    expect(err.message).toMatch(/unsupported|unknown/i);
    expect(srv.requests).toHaveLength(0); // never hit the network
  });
});
