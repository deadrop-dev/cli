import type { Readable, Writable } from "node:stream";
import { userError } from "./errors.js";

interface MaybeTTYReadable extends Readable {
  isTTY?: boolean;
  setRawMode?: (mode: boolean) => void;
}

/**
 * Prompt for a password. The prompt text goes to `output` (stderr in the CLI —
 * never stdout, so piped output stays clean; never echoes the password).
 *
 * - TTY stdin: raw mode, no echo, handles backspace and Ctrl+C.
 * - Non-TTY stdin: reads one line (scripting escape hatch).
 */
export function promptPassword(
  promptText: string,
  input: MaybeTTYReadable = process.stdin as MaybeTTYReadable,
  output: Writable = process.stderr,
): Promise<string> {
  output.write(promptText);

  if (input.isTTY && typeof input.setRawMode === "function") {
    return promptRawTTY(input, output);
  }
  return promptLine(input);
}

function promptRawTTY(input: MaybeTTYReadable, output: Writable): Promise<string> {
  return new Promise((resolve, reject) => {
    let value = "";
    input.setRawMode!(true);
    input.resume();

    const cleanup = () => {
      input.setRawMode!(false);
      input.pause();
      input.removeListener("data", onData);
      output.write("\n");
    };

    const onData = (chunk: Buffer) => {
      for (const byte of chunk) {
        if (byte === 0x03) {
          // Ctrl+C
          cleanup();
          reject(userError("Password entry cancelled."));
          return;
        }
        if (byte === 0x0d || byte === 0x0a) {
          // Enter
          cleanup();
          resolve(value);
          return;
        }
        if (byte === 0x7f || byte === 0x08) {
          // Backspace
          value = value.slice(0, -1);
          continue;
        }
        value += String.fromCharCode(byte);
      }
    };

    input.on("data", onData);
  });
}

function promptLine(input: Readable): Promise<string> {
  return new Promise((resolve, reject) => {
    let buf = "";
    const onData = (chunk: Buffer | string) => {
      buf += chunk.toString();
      const nl = buf.indexOf("\n");
      if (nl !== -1) {
        input.removeListener("data", onData);
        input.removeListener("end", onEnd);
        input.pause();
        resolve(buf.slice(0, nl).replace(/\r$/, ""));
      }
    };
    const onEnd = () => {
      input.removeListener("data", onData);
      reject(userError("No password provided (input closed before a line was read)."));
    };
    input.on("data", onData);
    input.on("end", onEnd);
  });
}

/** Read an entire stream (stdin pipe) as UTF-8. */
export function readAllStdin(input: Readable = process.stdin): Promise<string> {
  return new Promise((resolve, reject) => {
    let buf = "";
    input.setEncoding("utf8");
    input.on("data", (c: string) => (buf += c));
    input.on("end", () => resolve(buf));
    input.on("error", reject);
  });
}
