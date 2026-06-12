import { Command } from "commander";
import { defaultCtx } from "./commands/context.js";
import { runClaim } from "./commands/claim.js";
import { runConfig } from "./commands/config.js";
import { runFulfill } from "./commands/fulfill.js";
import { runQr } from "./commands/qr.js";
import { runReceive } from "./commands/receive.js";
import { runRequest } from "./commands/request.js";
import { runRevoke } from "./commands/revoke.js";
import { runSend } from "./commands/send.js";
import { CliError } from "./lib/errors.js";

const VERSION = "0.2.0";

/**
 * Exit codes: 0 success, 1 user error, 2 network/server error.
 * Errors go to stderr only — never secret material.
 */
function run(action: () => Promise<void>): Promise<void> {
  return action().catch((e: unknown) => {
    const message = e instanceof Error ? e.message : String(e);
    process.stderr.write(`error: ${message}\n`);
    process.exitCode = e instanceof CliError ? e.exitCode : 2;
  });
}

const program = new Command();

program
  .name("deadrop")
  .description("Zero-ceremony one-time secret sharing — client-side encrypted, burns on open.")
  .version(VERSION, "-v, --version", "Print version");

program
  .command("send [secret]")
  .description("Encrypt a secret and get a one-time link (reads stdin when piped)")
  .option("-s, --server <url>", "Server URL (default: https://deadrop.dev)")
  .option("-t, --ttl <duration>", "Time-to-live: 5m, 1h, 24h, 7d (default: 1h)")
  .option("-p, --password [password]", "Password-protect (prompts when no value given)")
  .option("--hint <hint>", "Password hint, shown to the recipient (max 140 chars)")
  .option("-j, --json", "Machine-readable JSON output")
  .option("-q, --quiet", "Print only the URL")
  .option("--qr", "Render a QR code after creating the link")
  .action((secret: string | undefined, opts) => run(() => runSend(secret, opts, defaultCtx())));

program
  .command("receive <url>")
  .description("Retrieve and decrypt a secret (burns it)")
  .option("-p, --password [password]", "Password for protected secrets (prompts otherwise)")
  .option("-j, --json", "Machine-readable JSON output")
  .option("-q, --quiet", "Print only the secret content")
  .action((url: string, opts) => run(() => runReceive(url, opts, defaultCtx())));

program
  .command("request [prompt]")
  .description("Ask someone for a secret — prints a request link to send and a claim link to keep")
  .option("-s, --server <url>", "Server URL (default: https://deadrop.dev)")
  .option("-t, --ttl <duration>", "Time-to-live: 5m, 1h, 24h, 7d (default: 24h)")
  .option("-j, --json", "Machine-readable JSON output")
  .option("-q, --quiet", "Print only the two links (request, then claim)")
  .option("--qr", "Render the request link as a QR code")
  .action((prompt: string | undefined, opts) => run(() => runRequest(prompt, opts, defaultCtx())));

program
  .command("fulfill <url> [secret]")
  .description("Answer a request link with a secret (reads stdin when piped)")
  .option("-j, --json", "Machine-readable JSON output")
  .option("-q, --quiet", "No output, exit code only")
  .action((url: string, secret: string | undefined, opts) =>
    run(() => runFulfill(url, secret, opts, defaultCtx())),
  );

program
  .command("claim <url>")
  .description("Claim and decrypt the response to your request (burns it; pending answers burn nothing)")
  .option("-j, --json", "Machine-readable JSON output")
  .option("-q, --quiet", "Print only the secret content")
  .action((url: string, opts) => run(() => runClaim(url, opts, defaultCtx())));

program
  .command("revoke <url>")
  .description("Destroy a secret before it is opened (needs the full URL — the server requires key proof)")
  .option("-p, --password [password]", "Password for protected secrets (prompts otherwise)")
  .option("-j, --json", "Machine-readable JSON output")
  .option("-q, --quiet", "No output, exit code only")
  .action((url: string, opts) => run(() => runRevoke(url, opts, defaultCtx())));

program
  .command("qr [url]")
  .description("Render a Deadrop link (or the last sent one) as a terminal QR code")
  .action((url: string | undefined, opts) => run(() => runQr(url, opts, defaultCtx())));

program
  .command("config <action> [key] [value]")
  .description("Manage configuration: set <key> <value> | get <key> | list | reset")
  .option("-j, --json", "JSON output for list")
  .action((action: string, key: string | undefined, value: string | undefined, opts) =>
    run(() => runConfig([action, key, value].filter((x): x is string => x !== undefined), opts, defaultCtx())),
  );

program.parseAsync().catch(() => {
  process.exitCode = 2;
});
