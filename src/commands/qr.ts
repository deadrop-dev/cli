import qrcode from "qrcode-terminal";
import { loadLastUrl } from "../config/store.js";
import { userError } from "../lib/errors.js";
import { parseSecretUrl } from "../lib/url.js";
import type { CommonFlags, Ctx } from "./context.js";

/** Render a URL as a small terminal QR code (string, trailing newline). */
export function renderQr(url: string): Promise<string> {
  return new Promise((resolve) => {
    qrcode.generate(url, { small: true }, (code) => resolve(code + "\n"));
  });
}

/**
 * `deadrop qr [url]` — render the given link, or the last sent one.
 * The QR encodes the full URL (key included) and is written to STDOUT only —
 * it is secret material, same as the link itself.
 */
export async function runQr(
  urlArg: string | undefined,
  _flags: CommonFlags,
  ctx: Ctx,
): Promise<void> {
  const url = urlArg ?? loadLastUrl(ctx.configFile);
  if (!url) {
    throw userError(
      "No URL given and no previously sent secret found. Usage: deadrop qr <url>",
    );
  }
  parseSecretUrl(url); // validate it is a Deadrop link (and refuse unknown KDFs)
  ctx.stdout.write(await renderQr(url));
}
