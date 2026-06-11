import type { OutputMode } from "./settings.js";
import { ttlToHuman } from "./ttl.js";

/**
 * Pipe detection: explicit json/quiet always win; human degrades to quiet
 * when stdout is not a TTY so pipes get only essential data.
 */
export function effectiveOutput(mode: OutputMode, stdoutIsTTY: boolean): OutputMode {
  if (mode === "human" && !stdoutIsTTY) return "quiet";
  return mode;
}

export interface SendResult {
  id: string;
  url: string;
  ttlMinutes: number;
  passwordProtected: boolean;
  expiresAt: Date;
}

export function formatSendResult(r: SendResult, mode: OutputMode): string {
  if (mode === "quiet") return r.url + "\n";
  if (mode === "json") {
    return (
      JSON.stringify({
        id: r.id,
        url: r.url,
        expires_at: r.expiresAt.toISOString(),
        ttl: r.ttlMinutes * 60,
        password_protected: r.passwordProtected,
      }) + "\n"
    );
  }
  return (
    "Secret created. Link (one-time, burns on open):\n" +
    "\n" +
    `  ${r.url}\n` +
    "\n" +
    `Expires in ${ttlToHuman(r.ttlMinutes)}.` +
    (r.passwordProtected ? " Password required to open." : "") +
    `\nRevoke: deadrop revoke "${r.url}"\n`
  );
}

export function formatReceiveResult(content: string, mode: OutputMode): string {
  if (mode === "quiet") return content;
  if (mode === "json") return JSON.stringify({ content, burned: true }) + "\n";
  return "Secret revealed (burned):\n\n" + content + "\n";
}
