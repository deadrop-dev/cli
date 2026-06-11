import { userError } from "./errors.js";

/** Server clamps expiresMinutes to [1, 10080] (SPEC v2.0). We validate client-side. */
export const MAX_TTL_MINUTES = 10080;

const UNIT_MINUTES: Record<string, number> = { m: 1, h: 60, d: 1440 };

/**
 * Parse a human TTL string ("5m", "1h", "24h", "7d", bare minutes "30")
 * into whole minutes. Throws CliError(1) on invalid input.
 */
export function parseTtl(input: string): number {
  const s = input.trim().toLowerCase();
  const m = /^(\d+)([mhd]?)$/.exec(s);
  if (!m) {
    throw userError(
      `Invalid TTL "${input}". Use forms like 5m, 1h, 24h, 7d (max 7d).`,
    );
  }
  const value = Number(m[1]);
  const unit = m[2] || "m";
  const minutes = value * (UNIT_MINUTES[unit] ?? 1);
  if (!Number.isInteger(minutes) || minutes < 1) {
    throw userError(`Invalid TTL "${input}". Must be at least 1 minute.`);
  }
  if (minutes > MAX_TTL_MINUTES) {
    throw userError(`Invalid TTL "${input}". Maximum is 7 days (10080 minutes).`);
  }
  return minutes;
}

/** Render minutes as a human-friendly duration ("1 hour 30 minutes"). */
export function ttlToHuman(minutes: number): string {
  const parts: string[] = [];
  const days = Math.floor(minutes / 1440);
  const hours = Math.floor((minutes % 1440) / 60);
  const mins = minutes % 60;
  if (days) parts.push(`${days} day${days === 1 ? "" : "s"}`);
  if (hours) parts.push(`${hours} hour${hours === 1 ? "" : "s"}`);
  if (mins) parts.push(`${mins} minute${mins === 1 ? "" : "s"}`);
  return parts.join(" ") || "0 minutes";
}
