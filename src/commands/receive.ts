import { loadConfig } from "../config/store.js";
import { getMeta, retrieveSecret, type RetrievedSecret } from "../lib/client.js";
import { openSecret, receiveCandidates, type ReceiveCandidate } from "../lib/crypto-flow.js";
import { CliError } from "../lib/errors.js";
import { effectiveOutput, formatReceiveResult } from "../lib/output.js";
import { resolveSettings } from "../lib/settings.js";
import { parseSecretUrl } from "../lib/url.js";
import type { CommonFlags, Ctx } from "./context.js";

export async function runReceive(
  urlArg: string,
  flags: CommonFlags,
  ctx: Ctx,
): Promise<void> {
  const parsed = parseSecretUrl(urlArg); // refuses unknown KDF prefixes before any network I/O
  const settings = resolveSettings(
    { json: flags.json, quiet: flags.quiet },
    ctx.env,
    loadConfig(ctx.configFile),
  );

  let password: string | undefined;
  if (parsed.kdf === "pbkdf2") {
    if (typeof flags.password === "string") {
      password = flags.password;
    } else {
      // Show the hint (semi-public, /meta needs no key proof) before prompting.
      try {
        const meta = await getMeta(parsed.server, parsed.id);
        if (meta.hint) ctx.stderr.write(`Hint: ${meta.hint}\n`);
      } catch {
        // Hint is best-effort; the retrieve call below reports real errors.
      }
      password = await ctx.promptPassword("Password: ");
    }
  } else if (flags.password !== undefined) {
    ctx.stderr.write("Note: this secret is not password-protected; ignoring --password.\n");
  }

  const candidates = await receiveCandidates(parsed.key, parsed.kdf, password);

  // Try candidates in order (NFC first, legacy raw second). A wrong hash gets
  // 403 WITHOUT burning, so trying the next candidate is safe.
  let blob: RetrievedSecret | undefined;
  let winner: ReceiveCandidate | undefined;
  for (let i = 0; i < candidates.length; i++) {
    const candidate = candidates[i]!;
    try {
      blob = await retrieveSecret(parsed.server, parsed.id, candidate.keyHash);
      winner = candidate;
      break;
    } catch (e) {
      const isLast = i === candidates.length - 1;
      if (e instanceof CliError && e.kind === "wrong-key" && !isLast) continue;
      throw e;
    }
  }

  const plaintext = await openSecret(blob!, winner!.key);
  const mode = effectiveOutput(settings.output, ctx.stdoutIsTTY);
  ctx.stdout.write(formatReceiveResult(plaintext, mode));
}
