import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { userError } from "../lib/errors.js";
import { parseTtl } from "../lib/ttl.js";

/** Keys accepted by `deadrop config set/get`. */
export const CONFIG_KEYS = ["server", "default-ttl", "output"] as const;
export type ConfigKey = (typeof CONFIG_KEYS)[number];

export type ConfigData = Partial<Record<ConfigKey, string>>;

export const OUTPUT_MODES = ["human", "json", "quiet"] as const;

/**
 * Config file location:
 * - $XDG_CONFIG_HOME/deadrop/config.json when XDG_CONFIG_HOME is set
 * - ~/.config/deadrop/config.json on POSIX
 * - ~/.deadrop/config.json on Windows (plan-specified fallback)
 */
export function configPath(
  env: Record<string, string | undefined> = process.env,
  platform: NodeJS.Platform = process.platform,
  home: string = homedir(),
): string {
  if (env.XDG_CONFIG_HOME) return join(env.XDG_CONFIG_HOME, "deadrop", "config.json");
  if (platform === "win32") return join(home, ".deadrop", "config.json");
  return join(home, ".config", "deadrop", "config.json");
}

function assertKey(key: string): asserts key is ConfigKey {
  if (!(CONFIG_KEYS as readonly string[]).includes(key)) {
    throw userError(
      `Unknown config key "${key}". Valid keys: ${CONFIG_KEYS.join(", ")}`,
    );
  }
}

function validateValue(key: ConfigKey, value: string): void {
  if (key === "server") {
    let u: URL | undefined;
    try {
      u = new URL(value);
    } catch {
      /* fallthrough */
    }
    if (!u || (u.protocol !== "https:" && u.protocol !== "http:")) {
      throw userError(`"${value}" is not a valid http(s) URL.`);
    }
  } else if (key === "default-ttl") {
    parseTtl(value); // throws on invalid / >7 days
  } else if (key === "output") {
    if (!(OUTPUT_MODES as readonly string[]).includes(value)) {
      throw userError(`Output mode must be one of: human, json, quiet.`);
    }
  }
}

/** Load config; missing or corrupt files are treated as empty. */
export function loadConfig(file: string): ConfigData {
  try {
    const raw = readFileSync(file, "utf8");
    const parsed = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return {};
    const out: ConfigData = {};
    for (const key of CONFIG_KEYS) {
      if (typeof parsed[key] === "string") out[key] = parsed[key];
    }
    return out;
  } catch {
    return {};
  }
}

function save(file: string, data: ConfigData): void {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(data, null, 2) + "\n", "utf8");
}

export function setConfigValue(file: string, key: string, value: string): void {
  assertKey(key);
  validateValue(key, value);
  const data = loadConfig(file);
  data[key] = value;
  save(file, data);
}

export function getConfigValue(file: string, key: string): string | undefined {
  assertKey(key);
  return loadConfig(file)[key];
}

/** Remove config file and last-url state. */
export function resetConfig(file: string): void {
  rmSync(file, { force: true });
  rmSync(lastUrlPath(file), { force: true });
}

function lastUrlPath(configFile: string): string {
  return join(dirname(configFile), "last-url");
}

/**
 * Persist the last sent secret URL so `deadrop qr` (no args) can render it.
 * NOTE: the URL contains the decryption key — this is a deliberate convenience
 * tradeoff from the plan. `deadrop config reset` clears it; it is overwritten
 * on every send.
 */
export function saveLastUrl(configFile: string, url: string): void {
  mkdirSync(dirname(lastUrlPath(configFile)), { recursive: true });
  writeFileSync(lastUrlPath(configFile), url + "\n", { encoding: "utf8", mode: 0o600 });
}

export function loadLastUrl(configFile: string): string | null {
  try {
    const v = readFileSync(lastUrlPath(configFile), "utf8").trim();
    return v || null;
  } catch {
    return null;
  }
}

// re-export for store tests / callers that need existence checks
export { existsSync as _existsSync };
