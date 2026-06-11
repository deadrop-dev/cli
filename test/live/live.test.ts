/**
 * LIVE integration tests against https://deadrop.dev.
 *
 * Excluded from `npm test` — run with `npm run test:live`.
 * Budget: exactly 3 create requests (server limit: 10 creates/min/IP).
 * On a 429 we wait once for the next minute boundary, then proceed.
 */
import { describe, it, expect } from "vitest";
import { makeCtx } from "../helpers/fake-ctx.js";
import { runSend } from "../../src/commands/send.js";
import { runReceive } from "../../src/commands/receive.js";
import { runRevoke } from "../../src/commands/revoke.js";
import { CliError } from "../../src/lib/errors.js";
import { parseSecretUrl } from "../../src/lib/url.js";

const SERVER = "https://deadrop.dev";

async function sendWith429Retry(
  fn: () => Promise<void>,
): Promise<void> {
  try {
    await fn();
  } catch (e) {
    if (e instanceof CliError && e.kind === "rate-limited") {
      const waitMs = (62 - new Date().getSeconds()) * 1000;
      await new Promise((r) => setTimeout(r, waitMs));
      await fn();
    } else {
      throw e;
    }
  }
}

describe("live deadrop.dev integration", () => {
  it("send → receive round-trip; second receive is gone", async () => {
    const secret = `live-roundtrip-${Date.now()}`;
    const s = makeCtx();
    await sendWith429Retry(() =>
      runSend(secret, { server: SERVER, ttl: "5m", quiet: true }, s.ctx),
    );
    const url = s.stdout().trim();
    expect(parseSecretUrl(url).server).toBe(SERVER);

    const r = makeCtx();
    await runReceive(url, { quiet: true }, r.ctx);
    expect(r.stdout()).toBe(secret);

    const r2 = makeCtx();
    const err = await runReceive(url, { quiet: true }, r2.ctx).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.exitCode).toBe(1);
    expect(err.kind).toBe("gone");
  }, 60_000);

  it("password-protected round-trip with hint", async () => {
    const secret = `live-pw-${Date.now()}`;
    const s = makeCtx();
    await sendWith429Retry(() =>
      runSend(
        secret,
        { server: SERVER, ttl: "5m", password: "live-test-pw", hint: "ci hint", quiet: true },
        s.ctx,
      ),
    );
    const url = s.stdout().trim();
    expect(parseSecretUrl(url).kdf).toBe("pbkdf2");

    // Prompt path exercises the /meta hint fetch too.
    const r = makeCtx({ promptPassword: async () => "live-test-pw" });
    await runReceive(url, { quiet: true }, r.ctx);
    expect(r.stdout()).toBe(secret);
    expect(r.stderr()).toContain("ci hint");
  }, 120_000);

  it("revoke kills the link before it is opened", async () => {
    const s = makeCtx();
    await sendWith429Retry(() =>
      runSend(`live-revoke-${Date.now()}`, { server: SERVER, ttl: "5m", quiet: true }, s.ctx),
    );
    const url = s.stdout().trim();

    const rv = makeCtx();
    await runRevoke(url, { quiet: true }, rv.ctx);

    const r = makeCtx();
    const err = await runReceive(url, { quiet: true }, r.ctx).catch((e) => e);
    expect(err).toBeInstanceOf(CliError);
    expect(err.kind).toBe("gone");
  }, 60_000);
});
