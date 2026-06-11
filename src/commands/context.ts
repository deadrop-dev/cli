import type { Readable } from "node:stream";
import { configPath } from "../config/store.js";
import { promptPassword } from "../lib/prompt.js";

export interface WriteSink {
  write(s: string): unknown;
}

/**
 * Injectable command context — everything a command touches outside its
 * arguments. Tests construct fakes; the real CLI uses defaultCtx().
 */
export interface Ctx {
  env: Record<string, string | undefined>;
  configFile: string;
  stdout: WriteSink;
  stderr: WriteSink;
  stdin: Readable;
  stdoutIsTTY: boolean;
  stdinIsTTY: boolean;
  promptPassword: (text: string) => Promise<string>;
  now: () => Date;
}

export function defaultCtx(): Ctx {
  return {
    env: process.env,
    configFile: configPath(),
    stdout: process.stdout,
    stderr: process.stderr,
    stdin: process.stdin,
    stdoutIsTTY: Boolean(process.stdout.isTTY),
    stdinIsTTY: Boolean(process.stdin.isTTY),
    promptPassword: (text) => promptPassword(text, process.stdin, process.stderr),
    now: () => new Date(),
  };
}

/** Flags shared across commands (commander option names). */
export interface CommonFlags {
  server?: string;
  ttl?: string;
  json?: boolean;
  quiet?: boolean;
  /** true = prompt interactively; string = inline value */
  password?: boolean | string;
  hint?: string;
  qr?: boolean;
}
