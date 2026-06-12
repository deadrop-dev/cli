import { loadConfig, saveLastUrl } from "../config/store.js";
import { createRequest, IdCollisionError } from "../lib/client.js";
import { userError, serverError } from "../lib/errors.js";
import { generateId } from "../lib/id.js";
import { effectiveOutput, formatRequestResult } from "../lib/output.js";
import { createRequestKeys } from "../lib/request-flow.js";
import { buildClaimUrl, buildRequestUrl } from "../lib/request-url.js";
import { resolveSettings } from "../lib/settings.js";
import type { CommonFlags, Ctx } from "./context.js";
import { renderQr } from "./qr.js";

const MAX_PROMPT_LENGTH = 140;

/** Requests default to 24h — the responder needs time to see the link. */
const DEFAULT_REQUEST_TTL = "24h";

export async function runRequest(
  promptArg: string | undefined,
  flags: CommonFlags,
  ctx: Ctx,
): Promise<void> {
  const config = loadConfig(ctx.configFile);
  const settings = resolveSettings(
    {
      ...flags,
      ttl: flags.ttl ?? ctx.env.DEADROP_TTL ?? config["default-ttl"] ?? DEFAULT_REQUEST_TTL,
    },
    ctx.env,
    config,
  );

  const prompt = promptArg?.trim() ?? "";
  if (prompt.length > MAX_PROMPT_LENGTH) {
    throw userError(`Prompt too long (max ${MAX_PROMPT_LENGTH} characters).`);
  }

  const keys = await createRequestKeys();

  // POST; on 409 id collision regenerate once and retry (same as send).
  let id = generateId();
  const payload = {
    publicKey: keys.publicKeyB64,
    claimProof: keys.claimProof,
    expiresMinutes: settings.ttlMinutes,
    ...(prompt ? { prompt } : {}),
  };
  try {
    await createRequest(settings.server, { id, ...payload });
  } catch (e) {
    if (!(e instanceof IdCollisionError)) throw e;
    id = generateId();
    try {
      await createRequest(settings.server, { id, ...payload });
    } catch (e2) {
      if (e2 instanceof IdCollisionError) {
        throw serverError(
          "Request id collided twice in a row — this should be statistically impossible. Server misbehaving?",
        );
      }
      throw e2;
    }
  }

  const requestUrl = buildRequestUrl(settings.server, id);
  const claimUrl = buildClaimUrl(settings.server, id, keys.privateKeyB64);
  saveLastUrl(ctx.configFile, requestUrl); // the shareable link, never the claim key

  const mode = effectiveOutput(settings.output, ctx.stdoutIsTTY);
  ctx.stdout.write(
    formatRequestResult(
      {
        id,
        requestUrl,
        claimUrl,
        fingerprint: keys.fingerprint,
        prompt,
        ttlMinutes: settings.ttlMinutes,
        expiresAt: new Date(ctx.now().getTime() + settings.ttlMinutes * 60_000),
      },
      mode,
    ),
  );

  if (flags.qr) {
    ctx.stdout.write(await renderQr(requestUrl));
  }
}
