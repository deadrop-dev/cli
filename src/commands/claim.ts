import { loadConfig } from "../config/store.js";
import { claimResponse } from "../lib/client.js";
import {
  effectiveOutput,
  formatClaimPending,
  formatClaimResult,
} from "../lib/output.js";
import {
  claimProofFromPrivate,
  fingerprintFromPrivate,
  openResponse,
} from "../lib/request-flow.js";
import { parseClaimUrl } from "../lib/request-url.js";
import { resolveSettings } from "../lib/settings.js";
import type { CommonFlags, Ctx } from "./context.js";

export async function runClaim(
  urlArg: string,
  flags: CommonFlags,
  ctx: Ctx,
): Promise<void> {
  const parsed = parseClaimUrl(urlArg); // key validity checked before any network I/O
  const settings = resolveSettings(
    { json: flags.json, quiet: flags.quiet },
    ctx.env,
    loadConfig(ctx.configFile),
  );

  // Proof and fingerprint both derive from the fragment key — a corrupted
  // link fails here, locally, before the server is involved.
  const proof = await claimProofFromPrivate(parsed.privateKey);
  const fingerprint = await fingerprintFromPrivate(parsed.privateKey);

  const result = await claimResponse(parsed.server, parsed.id, proof);
  const mode = effectiveOutput(settings.output, ctx.stdoutIsTTY);

  if (result.status === "pending") {
    // §9.3: 202 burns nothing — a normal outcome, exit 0. Note on stderr so
    // piped stdout stays empty rather than carrying a fake "secret".
    ctx.stderr.write("No answer yet — nothing was burned. Check again before it expires.\n");
    ctx.stdout.write(formatClaimPending(mode));
    return;
  }

  const plaintext = await openResponse(result.blob, parsed.privateKey);
  if (mode === "human") {
    ctx.stderr.write(`Key fingerprint ${fingerprint} — the sender saw this same code.\n`);
  }
  ctx.stdout.write(formatClaimResult(plaintext, mode));
}
