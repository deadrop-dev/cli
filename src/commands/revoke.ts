import { loadConfig } from "../config/store.js";
import { getMeta, revokeSecret } from "../lib/client.js";
import { receiveCandidates } from "../lib/crypto-flow.js";
import { CliError, userError } from "../lib/errors.js";
import { effectiveOutput } from "../lib/output.js";
import { resolveSettings } from "../lib/settings.js";
import { parseSecretUrl } from "../lib/url.js";
import type { CommonFlags, Ctx } from "./context.js";

/**
 * Revoke takes the FULL secret URL: the server requires the key-hash proof
 * (DELETE /api/secrets/{id}?k=...), which can only be computed from the URL
 * key (and the password, for password-protected secrets).
 */
export async function runRevoke(
  urlArg: string,
  flags: CommonFlags,
  ctx: Ctx,
): Promise<void> {
  let parsed;
  try {
    parsed = parseSecretUrl(urlArg);
  } catch (e) {
    if (e instanceof CliError && !urlArg.includes("://")) {
      throw userError(
        "Revoke requires the full secret URL (the server demands the key proof): " +
          'deadrop revoke "https://deadrop.dev/s/{id}#{key}"',
      );
    }
    throw e;
  }

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
      try {
        const meta = await getMeta(parsed.server, parsed.id);
        if (meta.hint) ctx.stderr.write(`Hint: ${meta.hint}\n`);
      } catch {
        // best-effort
      }
      password = await ctx.promptPassword("Password: ");
    }
  }

  const candidates = await receiveCandidates(parsed.key, parsed.kdf, password);
  for (let i = 0; i < candidates.length; i++) {
    try {
      await revokeSecret(parsed.server, parsed.id, candidates[i]!.keyHash);
      break;
    } catch (e) {
      const isLast = i === candidates.length - 1;
      if (e instanceof CliError && e.kind === "wrong-key" && !isLast) continue;
      throw e;
    }
  }

  const mode = effectiveOutput(settings.output, ctx.stdoutIsTTY);
  if (mode === "json") {
    ctx.stdout.write(JSON.stringify({ revoked: true, id: parsed.id }) + "\n");
  } else if (mode === "human") {
    ctx.stdout.write("Secret revoked. The link is now dead.\n");
  }
  // quiet: no output — exit code 0 says it all
}
