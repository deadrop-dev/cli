import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { startMockServer, type MockServer } from "../helpers/mock-server.js";
import { installFakeDeadrop, type FakeDeadrop } from "../helpers/fake-deadrop.js";
import { makeCtx } from "../helpers/fake-ctx.js";
import { runRequest } from "../../src/commands/request.js";
import { runFulfill } from "../../src/commands/fulfill.js";
import { runClaim } from "../../src/commands/claim.js";
import { parseClaimUrl, parseRequestUrl } from "../../src/lib/request-url.js";
import { computeClaimProof, computeFingerprint } from "@deadrop/crypto";
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

/** Create a request and return both links (quiet mode prints them in order). */
async function createRequestLinks(prompt?: string): Promise<{ requestUrl: string; claimUrl: string }> {
  const c = makeCtx();
  await runRequest(prompt, { server: srv.baseUrl, quiet: true }, c.ctx);
  const [requestUrl, claimUrl] = c.stdout().trim().split("\n") as [string, string];
  return { requestUrl, claimUrl };
}

describe("request → fulfill → claim round-trip (real crypto, real wire)", () => {
  it("round-trips a secret through the full reverse flow", async () => {
    const { requestUrl, claimUrl } = await createRequestLinks("the staging DB password");

    // request link carries no key material; claim link only in the fragment
    expect(requestUrl).not.toContain("#");
    const parsedClaim = parseClaimUrl(claimUrl);
    expect(parsedClaim.id).toBe(parseRequestUrl(requestUrl).id);

    // wire: POST body had exact §9 fields, prompt included, default TTL 24h
    const post = srv.requests.find((r) => r.method === "POST" && r.url === "/api/requests")!;
    const body = JSON.parse(post.body);
    expect(Object.keys(body).sort()).toEqual([
      "claimProof",
      "expiresMinutes",
      "id",
      "prompt",
      "publicKey",
    ]);
    expect(body.expiresMinutes).toBe(1440);
    expect(body.prompt).toBe("the staging DB password");
    expect(body.claimProof).toBe(await computeClaimProof(parsedClaim.privateKey));
    // the URL path never carries the claim proof or any key material
    expect(post.url).toBe("/api/requests");

    // fulfill: prompt + fingerprint surfaced on stderr before sending
    const f = makeCtx();
    await runFulfill(requestUrl, "hunter2 æøå 🔑", { quiet: true }, f.ctx);
    expect(f.stderr()).toContain("the staging DB password");
    expect(f.stderr()).toContain(await computeFingerprint(body.publicKey));

    // wire: fulfill body had exact §9 response fields
    const fpost = srv.requests.find((r) => r.method === "POST" && r.url.endsWith("/response"))!;
    expect(Object.keys(JSON.parse(fpost.body)).sort()).toEqual([
      "encrypted",
      "hkdfSalt",
      "iv",
      "responderPublicKey",
      "wrapIv",
      "wrappedKey",
    ]);

    // claim: decrypts byte-exact, burns the record
    const cl = makeCtx();
    await runClaim(claimUrl, { quiet: true }, cl.ctx);
    expect(cl.stdout()).toBe("hunter2 æøå 🔑");
    expect(fake.requests.size).toBe(0);

    // burned: second claim is a 404 user error
    const cl2 = makeCtx();
    const err = await runClaim(claimUrl, {}, cl2.ctx).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.kind).toBe("gone");
    expect(err.exitCode).toBe(1);
  });

  it("claim before fulfill is pending: exit normally, nothing burned, empty stdout", async () => {
    const { claimUrl } = await createRequestLinks();
    const cl = makeCtx();
    await runClaim(claimUrl, { quiet: true }, cl.ctx);
    expect(cl.stdout()).toBe("");
    expect(cl.stderr()).toContain("No answer yet");
    expect(fake.requests.size).toBe(1); // not burned

    const j = makeCtx();
    await runClaim(claimUrl, { json: true }, j.ctx);
    expect(JSON.parse(j.stdout())).toEqual({ status: "pending", burned: false });
  });

  it("a corrupted claim key fails locally — no network call, nothing burned", async () => {
    const { claimUrl } = await createRequestLinks();
    const broken = claimUrl.replace(/#.+$/, "#AAAA");
    srv.requests.length = 0;

    const cl = makeCtx();
    const err = await runClaim(broken, {}, cl.ctx).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.exitCode).toBe(1);
    expect(srv.requests.length).toBe(0); // failed before any wire I/O
    expect(fake.requests.size).toBe(1);
  });

  it("a wrong (but well-formed) claim key gets 403 and burns nothing", async () => {
    const { requestUrl, claimUrl } = await createRequestLinks();
    const f = makeCtx();
    await runFulfill(requestUrl, "guarded", { quiet: true }, f.ctx);

    // a second request's key against the first request's id
    const other = await createRequestLinks();
    const otherKey = parseClaimUrl(other.claimUrl).privateKey;
    const wrong = claimUrl.replace(/#.+$/, `#${otherKey}`);

    const cl = makeCtx();
    const err = await runClaim(wrong, {}, cl.ctx).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.kind).toBe("wrong-key");
    expect(fake.requests.size).toBe(2); // nothing burned

    // the right key still works afterwards
    const good = makeCtx();
    await runClaim(claimUrl, { quiet: true }, good.ctx);
    expect(good.stdout()).toBe("guarded");
  });

  it("second fulfill is rejected with conflict; the original response survives", async () => {
    const { requestUrl, claimUrl } = await createRequestLinks();
    const f1 = makeCtx();
    await runFulfill(requestUrl, "first answer", { quiet: true }, f1.ctx);

    const f2 = makeCtx();
    const err = await runFulfill(requestUrl, "second answer", { quiet: true }, f2.ctx).catch(
      (e) => e,
    );
    expect(err).toBeInstanceOf(CliError);
    expect(err.kind).toBe("conflict");
    expect(err.exitCode).toBe(1);

    const cl = makeCtx();
    await runClaim(claimUrl, { quiet: true }, cl.ctx);
    expect(cl.stdout()).toBe("first answer");
  });

  it("fulfill reads the secret from stdin when piped", async () => {
    const { requestUrl, claimUrl } = await createRequestLinks();
    const f = makeCtx({ stdinIsTTY: false });
    f.stdin.end("piped answer");
    await runFulfill(requestUrl, undefined, { quiet: true }, f.ctx);

    const cl = makeCtx();
    await runClaim(claimUrl, { quiet: true }, cl.ctx);
    expect(cl.stdout()).toBe("piped answer");
  });

  it("request without a prompt sends no prompt field; status returns empty string", async () => {
    const { requestUrl } = await createRequestLinks();
    const post = srv.requests.find((r) => r.method === "POST" && r.url === "/api/requests")!;
    expect("prompt" in JSON.parse(post.body)).toBe(false);

    const f = makeCtx({ stdinIsTTY: false });
    f.stdin.end("x");
    await runFulfill(requestUrl, undefined, { quiet: true }, f.ctx);
    expect(f.stderr()).not.toContain("asking for");
  });

  it("rejects a prompt over 140 characters before any network call", async () => {
    const c = makeCtx();
    const err = await runRequest("x".repeat(141), { server: srv.baseUrl }, c.ctx).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(srv.requests.length).toBe(0);
  });

  it("id collision on create regenerates once and retries (same as send)", async () => {
    fake.collideNext = 1;
    const c = makeCtx();
    await runRequest(undefined, { server: srv.baseUrl, quiet: true }, c.ctx);
    const posts = srv.requests.filter((r) => r.method === "POST");
    expect(posts.length).toBe(2);
    expect(JSON.parse(posts[0]!.body).id).not.toBe(JSON.parse(posts[1]!.body).id);
  });

  it("human request output shows both links, fingerprint, and the loss warning", async () => {
    const c = makeCtx();
    await runRequest("api key", { server: srv.baseUrl }, c.ctx);
    const out = c.stdout();
    expect(out).toContain("/r/");
    expect(out).toContain("/claim#");
    expect(out).toMatch(/fingerprint [A-Za-z0-9_-]{8}/);
    expect(out).toContain("lose it and nobody can decrypt");
  });
});
