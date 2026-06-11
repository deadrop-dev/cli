import { userError } from "./errors.js";
import { parseTtl } from "./ttl.js";
import type { ConfigData } from "../config/store.js";

export const DEFAULT_SERVER = "https://deadrop.dev";
export const DEFAULT_TTL = "1h";

export type OutputMode = "human" | "json" | "quiet";

export interface Flags {
  server?: string;
  ttl?: string;
  json?: boolean;
  quiet?: boolean;
}

export interface Settings {
  server: string;
  ttlMinutes: number;
  output: OutputMode;
}

function normalizeServer(raw: string): string {
  let u: URL | undefined;
  try {
    u = new URL(raw);
  } catch {
    /* fallthrough */
  }
  if (!u || (u.protocol !== "https:" && u.protocol !== "http:")) {
    throw userError(`"${raw}" is not a valid http(s) server URL.`);
  }
  return raw.replace(/\/+$/, "");
}

/**
 * Resolve effective settings. Precedence: flags > env > config > defaults.
 * For output mode, --json beats --quiet when both flags are given.
 */
export function resolveSettings(
  flags: Flags,
  env: Record<string, string | undefined> = process.env,
  config: ConfigData = {},
): Settings {
  const server = normalizeServer(
    flags.server ?? env.DEADROP_SERVER ?? config.server ?? DEFAULT_SERVER,
  );

  const ttlMinutes = parseTtl(
    flags.ttl ?? env.DEADROP_TTL ?? config["default-ttl"] ?? DEFAULT_TTL,
  );

  let output: OutputMode;
  if (flags.json) output = "json";
  else if (flags.quiet) output = "quiet";
  else {
    const envOut = env.DEADROP_OUTPUT ?? config.output;
    if (envOut !== undefined && !["human", "json", "quiet"].includes(envOut)) {
      throw userError(`Output mode must be one of: human, json, quiet (got "${envOut}").`);
    }
    output = (envOut as OutputMode | undefined) ?? "human";
  }

  return { server, ttlMinutes, output };
}
