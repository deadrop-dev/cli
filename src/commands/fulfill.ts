import { loadConfig } from "../config/store.js";
import { AlreadyFulfilledError, fulfillRequest, getRequestStatus } from "../lib/client.js";
import { CliError, userError } from "../lib/errors.js";
import { effectiveOutput, formatFulfillResult } from "../lib/output.js";
import { readAllStdin } from "../lib/prompt.js";
import { fingerprintOfPublic, sealForRequest } from "../lib/request-flow.js";
import { parseRequestUrl } from "../lib/request-url.js";
import { resolveSettings } from "../lib/settings.js";
import type { CommonFlags, Ctx } from "./context.js";

export async function runFulfill(
  urlArg: string,
  secretArg: string | undefined,
  flags: CommonFlags,
  ctx: Ctx,
): Promise<void> {
  const parsed = parseRequestUrl(urlArg); // host from the URL, like receive
  const settings = resolveSettings(
    { json: flags.json, quiet: flags.quiet },
    ctx.env,
    loadConfig(ctx.configFile),
  );

  const status = await getRequestStatus(parsed.server, parsed.id);
  if (status.fulfilled) {
    throw new CliError(
      "This request was already answered — each request takes exactly one response.",
      1,
      "conflict",
    );
  }

  // §9.4: surface the fingerprint and the (semi-public) prompt BEFORE the
  // secret is read, so the responder can verify out-of-band. stderr, so
  // quiet/json stdout stays clean.
  const fingerprint = await fingerprintOfPublic(status.publicKey);
  if (status.prompt) ctx.stderr.write(`They're asking for: ${status.prompt}\n`);
  ctx.stderr.write(
    `Key fingerprint ${fingerprint} — ask the requester to confirm theirs matches.\n`,
  );

  // Secret: inline arg, or stdin when piped (same contract as send).
  let plaintext: string;
  if (secretArg !== undefined) {
    plaintext = secretArg;
  } else if (!ctx.stdinIsTTY) {
    plaintext = await readAllStdin(ctx.stdin);
  } else {
    throw userError(
      'No secret provided. Pass it as an argument (deadrop fulfill <url> "secret") or pipe it via stdin.',
    );
  }
  if (plaintext.length === 0) {
    throw userError("Refusing to send an empty secret.");
  }

  const blob = await sealForRequest(plaintext, status.publicKey);
  try {
    await fulfillRequest(parsed.server, parsed.id, blob);
  } catch (e) {
    if (e instanceof AlreadyFulfilledError) {
      throw new CliError(e.message, 1, "conflict");
    }
    throw e;
  }

  const mode = effectiveOutput(settings.output, ctx.stdoutIsTTY);
  ctx.stdout.write(formatFulfillResult(fingerprint, mode));
}
