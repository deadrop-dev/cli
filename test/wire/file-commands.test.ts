import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { startMockServer, type MockServer } from "../helpers/mock-server.js";
import { installFakeDeadrop, type FakeDeadrop } from "../helpers/fake-deadrop.js";
import { makeCtx } from "../helpers/fake-ctx.js";
import { runSend } from "../../src/commands/send.js";
import { runReceive } from "../../src/commands/receive.js";
import { runFulfill } from "../../src/commands/fulfill.js";
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

const sha256 = (b: Uint8Array | Buffer) => createHash("sha256").update(b).digest("hex");

/** Deterministic binary spanning all byte values, clearly not UTF-8 text. */
function makeBinaryFile(name: string, size = 4096): { path: string; bytes: Buffer } {
  const dir = mkdtempSync(join(tmpdir(), "deadrop-file-"));
  const bytes = Buffer.alloc(size);
  for (let i = 0; i < size; i++) bytes[i] = (i * 7 + 13) & 0xff;
  const path = join(dir, name);
  writeFileSync(path, bytes);
  return { path, bytes };
}

async function sendFile(path: string): Promise<string> {
  const c = makeCtx();
  await runSend(undefined, { server: srv.baseUrl, quiet: true, file: path }, c.ctx);
  return c.stdout().trim();
}

describe("send --file → receive (real crypto, real wire)", () => {
  it("round-trips a binary file byte-identically to cwd", async () => {
    const { path, bytes } = makeBinaryFile("night report.bin");
    const url = await sendFile(path);
    expect(url).toMatch(/\/s\/[A-Za-z0-9_-]{32}#/);

    const r = makeCtx();
    await runReceive(url, {}, r.ctx);
    const written = join(r.dir, "night report.bin");
    expect(existsSync(written)).toBe(true);
    expect(sha256(readFileSync(written))).toBe(sha256(bytes));
    expect(r.stdout()).toContain("night report.bin");
    expect(r.stdout()).toContain("4.0 KB");
    expect(fake.store.size).toBe(0); // burned
  });

  it("wire shape of a file create is identical to a text create", async () => {
    const { path } = makeBinaryFile("shape.bin", 128);
    await sendFile(path);
    const filePost = srv.requests.find((r) => r.method === "POST" && r.url === "/api/secrets")!;

    srv.requests.length = 0;
    const t = makeCtx();
    await runSend("plain text", { server: srv.baseUrl, quiet: true }, t.ctx);
    const textPost = srv.requests.find((r) => r.method === "POST" && r.url === "/api/secrets")!;

    expect(Object.keys(JSON.parse(filePost.body)).sort()).toEqual(
      Object.keys(JSON.parse(textPost.body)).sort(),
    );
    // nothing file-ish leaks in the request body
    expect(filePost.body).not.toContain("shape.bin");
    expect(filePost.body).not.toContain("file/v1");
  });

  it("--out writes to the given path; quiet prints the path", async () => {
    const { path, bytes } = makeBinaryFile("data.bin", 512);
    const url = await sendFile(path);

    const r = makeCtx();
    const target = join(r.dir, "renamed.dat");
    await runReceive(url, { out: target, quiet: true }, r.ctx);
    expect(sha256(readFileSync(target))).toBe(sha256(bytes));
    expect(r.stdout().trim()).toBe(target);
  });

  it("piped stdout gets raw bytes only, writes no file", async () => {
    const { path, bytes } = makeBinaryFile("piped.bin", 2048);
    const url = await sendFile(path);

    const r = makeCtx({ stdoutIsTTY: false });
    await runReceive(url, {}, r.ctx);
    expect(sha256(r.stdoutBytes())).toBe(sha256(bytes));
    expect(existsSync(join(r.dir, "piped.bin"))).toBe(false);
  });

  it("refuses to overwrite without --force, overwrites with it", async () => {
    const { path, bytes } = makeBinaryFile("clobber.bin", 256);
    const url1 = await sendFile(path);

    const r = makeCtx();
    const target = join(r.dir, "clobber.bin");
    writeFileSync(target, "precious");

    const err = await runReceive(url1, {}, r.ctx).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.exitCode).toBe(1);
    expect(err.message).toContain("--force");
    expect(readFileSync(target, "utf8")).toBe("precious"); // untouched
    expect(fake.store.size).toBe(0); // already burned by the retrieve

    const url2 = await sendFile(path);
    await runReceive(url2, { force: true }, r.ctx);
    expect(sha256(readFileSync(target))).toBe(sha256(bytes));
  });

  it("hostile filename from a handcrafted envelope is sanitized into cwd", async () => {
    const hostile = '{"dd":"file/v1","name":"../../evil<>.bin","type":"","data":"AAEC"}';
    const c = makeCtx();
    await runSend(hostile, { server: srv.baseUrl, quiet: true }, c.ctx);
    const url = c.stdout().trim();

    const r = makeCtx();
    await runReceive(url, {}, r.ctx);
    const written = join(r.dir, ".._.._evil__.bin");
    expect(existsSync(written)).toBe(true);
    expect(Array.from(readFileSync(written))).toEqual([0, 1, 2]);
    expect(existsSync(join(r.dir, "..", "evil<>.bin"))).toBe(false);
  });

  it("--out pre-flight fails BEFORE the retrieve — the secret survives", async () => {
    const { path } = makeBinaryFile("preflight.bin", 64);
    const url = await sendFile(path);

    const r = makeCtx();
    const target = join(r.dir, "taken.bin");
    writeFileSync(target, "occupied");
    const err = await runReceive(url, { out: target }, r.ctx).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.message).toContain("--force");
    expect(fake.store.size).toBe(1); // NOT burned — the doomed write was caught pre-network
    expect(readFileSync(target, "utf8")).toBe("occupied");

    // and the same link still works afterwards
    await runReceive(url, { out: target, force: true }, r.ctx);
    expect(fake.store.size).toBe(0);
  });

  it("text secret with --out is written as bytes", async () => {
    const c = makeCtx();
    await runSend("api-key-π-🔑", { server: srv.baseUrl, quiet: true }, c.ctx);
    const url = c.stdout().trim();

    const r = makeCtx();
    const target = join(r.dir, "secret.txt");
    await runReceive(url, { out: target }, r.ctx);
    expect(readFileSync(target, "utf8")).toBe("api-key-π-🔑");
  });
});

describe("send --file guards (all local, pre-network)", () => {
  it("rejects a file over 256 KiB without any network call", async () => {
    const { path } = makeBinaryFile("big.bin", 262_145);
    const c = makeCtx();
    const err = await runSend(undefined, { server: srv.baseUrl, file: path }, c.ctx).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.exitCode).toBe(1);
    expect(err.message).toContain("too large");
    expect(srv.requests.filter((r) => r.url === "/api/secrets")).toHaveLength(0);
  });

  it("rejects --file combined with an inline secret", async () => {
    const { path } = makeBinaryFile("both.bin", 16);
    const c = makeCtx();
    const err = await runSend("inline too", { server: srv.baseUrl, file: path }, c.ctx).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.message).toContain("mutually exclusive");
    expect(srv.requests.filter((r) => r.url === "/api/secrets")).toHaveLength(0);
  });

  it("rejects an empty file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "deadrop-file-"));
    const path = join(dir, "empty.bin");
    writeFileSync(path, "");
    const c = makeCtx();
    const err = await runSend(undefined, { server: srv.baseUrl, file: path }, c.ctx).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.message).toContain("empty file");
  });

  it("rejects an unreadable path with a clear message", async () => {
    const c = makeCtx();
    const err = await runSend(undefined, { server: srv.baseUrl, file: "Z:/no/such/file.bin" }, c.ctx).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.message).toContain("Cannot read file");
  });
});

describe("fulfill --file", () => {
  it("is rejected honestly before any network call", async () => {
    const c = makeCtx();
    const err = await runFulfill(
      `${srv.baseUrl}/r/${"A".repeat(32)}`,
      undefined,
      { file: "whatever.bin" },
      c.ctx,
    ).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.exitCode).toBe(1);
    expect(err.message).toContain("not supported for requests");
    expect(err.message).toContain("deadrop send --file");
    expect(srv.requests).toHaveLength(0);
  });
});
