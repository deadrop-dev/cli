import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { loadConfig, saveLastUrl } from "../config/store.js";
import { createSecret, IdCollisionError } from "../lib/client.js";
import { sealSecret } from "../lib/crypto-flow.js";
import { serverError, userError } from "../lib/errors.js";
import {
  encodeFileEnvelope,
  humanFileSize,
  MAX_FILE_BYTES,
  mimeFromName,
} from "../lib/file-envelope.js";
import { generateId } from "../lib/id.js";
import { effectiveOutput, formatSendResult } from "../lib/output.js";
import { readAllStdin } from "../lib/prompt.js";
import { resolveSettings } from "../lib/settings.js";
import { buildSecretUrl } from "../lib/url.js";
import type { CommonFlags, Ctx } from "./context.js";
import { renderQr } from "./qr.js";

const MAX_HINT_LENGTH = 140;

export async function runSend(
  secretArg: string | undefined,
  flags: CommonFlags,
  ctx: Ctx,
): Promise<void> {
  const settings = resolveSettings(flags, ctx.env, loadConfig(ctx.configFile));

  // Secret: --file, inline arg, or stdin when piped.
  let plaintext: string;
  if (flags.file !== undefined) {
    if (secretArg !== undefined) {
      throw userError("--file and an inline secret are mutually exclusive — pass one or the other.");
    }
    // stdin is deliberately not consumed with --file: a non-TTY stdin is
    // normal in scripts and CI, so requiring a TTY here would break them.
    let bytes: Buffer;
    try {
      bytes = readFileSync(flags.file);
    } catch {
      throw userError(`Cannot read file: ${flags.file}`);
    }
    if (bytes.length === 0) {
      throw userError("Refusing to send an empty file.");
    }
    if (bytes.length > MAX_FILE_BYTES) {
      // Exact bytes, not rounded units — near the boundary "256.0 KB vs
      // 256.0 KB" reads like nonsense.
      throw userError(
        `File is too large: ${bytes.length.toLocaleString("en-US")} bytes (max ${MAX_FILE_BYTES.toLocaleString("en-US")} = 256 KiB).`,
      );
    }
    const name = basename(flags.file);
    plaintext = encodeFileEnvelope(name, mimeFromName(name), new Uint8Array(bytes));
  } else if (secretArg !== undefined) {
    plaintext = secretArg;
  } else if (!ctx.stdinIsTTY) {
    plaintext = await readAllStdin(ctx.stdin);
  } else {
    throw userError(
      'No secret provided. Pass it as an argument (deadrop send "secret"), pipe it via stdin, or use --file.',
    );
  }
  if (plaintext.length === 0) {
    throw userError("Refusing to send an empty secret.");
  }

  // Password: --password with value, or interactive double prompt.
  let password: string | undefined;
  if (typeof flags.password === "string") {
    password = flags.password;
  } else if (flags.password === true) {
    const first = await ctx.promptPassword("Password: ");
    const second = await ctx.promptPassword("Confirm password: ");
    if (first !== second) throw userError("Passwords do not match.");
    if (first.length === 0) throw userError("Password must not be empty.");
    password = first;
  }

  if (flags.hint !== undefined) {
    if (password === undefined) {
      throw userError("--hint requires --password (hints describe the password).");
    }
    if (flags.hint.length > MAX_HINT_LENGTH) {
      throw userError(`Hint too long (max ${MAX_HINT_LENGTH} characters).`);
    }
  }

  const sealed = await sealSecret(plaintext, { password });

  // POST; on 409 id collision regenerate once and retry.
  let id = generateId();
  const payload = {
    encrypted: sealed.encrypted,
    iv: sealed.iv,
    keyHash: sealed.keyHash,
    expiresMinutes: settings.ttlMinutes,
    ...(flags.hint !== undefined ? { hint: flags.hint } : {}),
  };
  try {
    await createSecret(settings.server, { id, ...payload });
  } catch (e) {
    if (!(e instanceof IdCollisionError)) throw e;
    id = generateId();
    try {
      await createSecret(settings.server, { id, ...payload });
    } catch (e2) {
      if (e2 instanceof IdCollisionError) {
        throw serverError(
          "Secret id collided twice in a row — this should be statistically impossible. Server misbehaving?",
        );
      }
      throw e2;
    }
  }

  const url = buildSecretUrl(settings.server, id, sealed.keyB64, sealed.passwordProtected);
  saveLastUrl(ctx.configFile, url);

  const mode = effectiveOutput(settings.output, ctx.stdoutIsTTY);
  ctx.stdout.write(
    formatSendResult(
      {
        id,
        url,
        ttlMinutes: settings.ttlMinutes,
        passwordProtected: sealed.passwordProtected,
        expiresAt: new Date(ctx.now().getTime() + settings.ttlMinutes * 60_000),
      },
      mode,
    ),
  );

  if (flags.qr) {
    ctx.stdout.write(await renderQr(url));
  }
}
