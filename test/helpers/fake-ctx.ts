import { PassThrough } from "node:stream";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Ctx } from "../../src/commands/context.js";

export interface FakeCtx {
  ctx: Ctx;
  stdout: () => string;
  stderr: () => string;
  stdin: PassThrough;
}

export function makeCtx(overrides: Partial<Ctx> = {}): FakeCtx {
  let out = "";
  let err = "";
  const stdin = new PassThrough();
  const dir = mkdtempSync(join(tmpdir(), "deadrop-ctx-"));

  const ctx: Ctx = {
    env: {},
    configFile: join(dir, "config.json"),
    stdout: { write: (s: string) => ((out += s), true) },
    stderr: { write: (s: string) => ((err += s), true) },
    stdin,
    stdoutIsTTY: true,
    stdinIsTTY: true,
    promptPassword: async () => {
      throw new Error("promptPassword not stubbed");
    },
    now: () => new Date("2026-06-12T10:00:00Z"),
    ...overrides,
  };

  return { ctx, stdout: () => out, stderr: () => err, stdin };
}
