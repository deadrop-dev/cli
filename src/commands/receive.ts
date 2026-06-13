import { existsSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadConfig } from "../config/store.js";
import { getMeta, retrieveSecret, type RetrievedSecret } from "../lib/client.js";
import { openSecret, receiveCandidates, type ReceiveCandidate } from "../lib/crypto-flow.js";
import { CliError, userError } from "../lib/errors.js";
import { decodeFileEnvelope, sanitizeFilename } from "../lib/file-envelope.js";
import { effectiveOutput, formatFileReceiveResult, formatReceiveResult } from "../lib/output.js";
import { resolveSettings } from "../lib/settings.js";
import { parseSecretUrl } from "../lib/url.js";
import type { CommonFlags, Ctx } from "./context.js";

/** Clobber/dir checks, shared by the pre-flight and the actual write. */
function assertWritableTarget(target: string, force: boolean): void {
  if (!existsSync(target)) return;
  if (statSync(target).isDirectory()) {
    throw userError(`${target} is a directory — pass a file path.`);
  }
  if (!force) {
    throw userError(`File exists: ${target}. Use --force to overwrite.`);
  }
}

/** Write payload bytes to disk, refusing to clobber without --force. */
function writePayloadFile(target: string, bytes: Uint8Array, force: boolean): void {
  assertWritableTarget(target, force);
  writeFileSync(target, bytes);
}

export async function runReceive(
  urlArg: string,
  flags: CommonFlags,
  ctx: Ctx,
): Promise<void> {
  const parsed = parseSecretUrl(urlArg); // refuses unknown KDF prefixes before any network I/O
  // Pre-flight the --out target BEFORE the retrieve: retrieval burns the
  // secret, so a doomed write (existing file, directory target) must fail
  // while the secret is still alive. The default-cwd path can't get this —
  // its filename only exists inside the ciphertext.
  if (flags.out !== undefined) {
    assertWritableTarget(flags.out, flags.force === true);
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

  // File mode: detection is a pure view over the decrypted text — the wire
  // never says "file", exactly like the web client.
  const file = decodeFileEnvelope(plaintext);

  if (!file) {
    if (flags.out !== undefined) {
      const bytes = new TextEncoder().encode(plaintext);
      writePayloadFile(flags.out, bytes, flags.force === true);
      ctx.stdout.write(formatFileReceiveResult(
        { name: flags.out, size: bytes.length, path: flags.out },
        mode,
      ));
      return;
    }
    ctx.stdout.write(formatReceiveResult(plaintext, mode));
    return;
  }

  if (flags.out !== undefined) {
    writePayloadFile(flags.out, file.bytes, flags.force === true);
    ctx.stdout.write(formatFileReceiveResult(
      { name: sanitizeFilename(file.name), size: file.bytes.length, path: flags.out },
      mode,
    ));
    return;
  }

  if (mode === "quiet") {
    // Piped or --quiet: raw bytes to stdout, nothing else.
    ctx.stdout.write(file.bytes);
    return;
  }

  const name = sanitizeFilename(file.name);
  const target = join(ctx.cwd(), name);
  writePayloadFile(target, file.bytes, flags.force === true);
  ctx.stdout.write(formatFileReceiveResult(
    { name, size: file.bytes.length, path: target },
    mode,
  ));
}
