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

export interface RequestResult {
  id: string;
  requestUrl: string;
  claimUrl: string;
  fingerprint: string;
  prompt: string;
  ttlMinutes: number;
  expiresAt: Date;
}

/** Quiet prints request link then claim link, one per line (pipe-friendly). */
export function formatRequestResult(r: RequestResult, mode: OutputMode): string {
  if (mode === "quiet") return `${r.requestUrl}\n${r.claimUrl}\n`;
  if (mode === "json") {
    return (
      JSON.stringify({
        id: r.id,
        request_url: r.requestUrl,
        claim_url: r.claimUrl,
        fingerprint: r.fingerprint,
        prompt: r.prompt,
        expires_at: r.expiresAt.toISOString(),
        ttl: r.ttlMinutes * 60,
      }) + "\n"
    );
  }
  return (
    "Request created. Two links, two jobs:\n" +
    "\n" +
    "Send this to the person with the secret:\n" +
    `  ${r.requestUrl}\n` +
    "\n" +
    "Keep this — the ONLY key to the response (lose it and nobody can decrypt):\n" +
    `  ${r.claimUrl}\n` +
    "\n" +
    `Key fingerprint ${r.fingerprint} — the responder sees the same code if nothing was tampered with.\n` +
    `Expires in ${ttlToHuman(r.ttlMinutes)}, or after the response is claimed.\n` +
    `Claim: deadrop claim "${r.claimUrl}"\n`
  );
}

export function formatFulfillResult(fingerprint: string, mode: OutputMode): string {
  if (mode === "quiet") return "";
  if (mode === "json") return JSON.stringify({ fulfilled: true, fingerprint }) + "\n";
  return (
    "Secret sent — encrypted locally, only the requester's claim link can decrypt it.\n" +
    `Key fingerprint ${fingerprint} — ask the requester to confirm theirs matches.\n`
  );
}

/** 202 pending: nothing burned; stdout stays clean outside json mode. */
export function formatClaimPending(mode: OutputMode): string {
  if (mode === "json") return JSON.stringify({ status: "pending", burned: false }) + "\n";
  return "";
}

export function formatClaimResult(content: string, mode: OutputMode): string {
  if (mode === "quiet") return content;
  if (mode === "json") return JSON.stringify({ status: "claimed", content, burned: true }) + "\n";
  return "Response decrypted (burned):\n\n" + content + "\n";
}
