import {
  CONFIG_KEYS,
  getConfigValue,
  loadConfig,
  resetConfig,
  setConfigValue,
} from "../config/store.js";
import { userError } from "../lib/errors.js";
import type { CommonFlags, Ctx } from "./context.js";

/**
 * `deadrop config set <key> <value> | get <key> | list | reset`
 */
export async function runConfig(
  args: string[],
  flags: CommonFlags,
  ctx: Ctx,
): Promise<void> {
  const [action, key, value] = args;

  switch (action) {
    case "set": {
      if (!key || value === undefined) {
        throw userError("Usage: deadrop config set <key> <value>");
      }
      setConfigValue(ctx.configFile, key, value);
      return;
    }
    case "get": {
      if (!key) throw userError("Usage: deadrop config get <key>");
      const v = getConfigValue(ctx.configFile, key);
      if (v !== undefined) ctx.stdout.write(v + "\n");
      return;
    }
    case "list": {
      const data = loadConfig(ctx.configFile);
      if (flags.json) {
        ctx.stdout.write(JSON.stringify(data) + "\n");
        return;
      }
      for (const k of CONFIG_KEYS) {
        if (data[k] !== undefined) ctx.stdout.write(`${k}=${data[k]}\n`);
      }
      return;
    }
    case "reset": {
      resetConfig(ctx.configFile);
      return;
    }
    default:
      throw userError(
        `Unknown config action "${action ?? ""}". Use: set, get, list, reset.`,
      );
  }
}
