import { PassThrough } from "node:stream";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Ctx } from "../../src/commands/context.js";

export interface FakeCtx {
  ctx: Ctx;
  stdout: () => string;
  /** Raw stdout including binary chunks (file-mode piped output). */
  stdoutBytes: () => Buffer;
  stderr: () => string;
  stdin: PassThrough;
  /** Isolated temp dir used as configFile home AND ctx.cwd(). */
  dir: string;
}

export function makeCtx(overrides: Partial<Ctx> = {}): FakeCtx {
  let out = "";
  let err = "";
  const chunks: (string | Uint8Array)[] = [];
  const stdin = new PassThrough();
  const dir = mkdtempSync(join(tmpdir(), "deadrop-ctx-"));

  const ctx: Ctx = {
    env: {},
    configFile: join(dir, "config.json"),
    stdout: {
      write: (s: string | Uint8Array) => {
        chunks.push(s);
        if (typeof s === "string") out += s;
        return true;
      },
    },
    stderr: { write: (s: string | Uint8Array) => ((err += String(s)), true) },
    stdin,
    stdoutIsTTY: true,
    stdinIsTTY: true,
    promptPassword: async () => {
      throw new Error("promptPassword not stubbed");
    },
    now: () => new Date("2026-06-12T10:00:00Z"),
    cwd: () => dir,
    ...overrides,
  };

  return {
    ctx,
    stdout: () => out,
    stdoutBytes: () =>
      Buffer.concat(chunks.map((c) => (typeof c === "string" ? Buffer.from(c, "utf8") : Buffer.from(c)))),
    stderr: () => err,
    stdin,
    dir,
  };
}
