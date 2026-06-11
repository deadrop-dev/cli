import { describe, it, expect } from "vitest";
import { PassThrough } from "node:stream";
import { promptPassword, readAllStdin } from "../../src/lib/prompt.js";

function collect(): { stream: PassThrough; data: () => string } {
  const stream = new PassThrough();
  let buf = "";
  stream.on("data", (c) => (buf += c.toString("utf8")));
  return { stream, data: () => buf };
}

describe("promptPassword (non-TTY streams, function level)", () => {
  it("writes the prompt to the OUTPUT stream (stderr), never the password", async () => {
    const input = new PassThrough();
    const out = collect();
    const p = promptPassword("Password: ", input, out.stream);
    input.write("hunter2\n");
    const result = await p;
    expect(result).toBe("hunter2");
    expect(out.data()).toContain("Password: ");
    expect(out.data()).not.toContain("hunter2");
  });

  it("strips trailing CRLF (Windows line endings)", async () => {
    const input = new PassThrough();
    const out = collect();
    const p = promptPassword("pw: ", input, out.stream);
    input.write("s3cret\r\n");
    expect(await p).toBe("s3cret");
  });

  it("rejects on closed input without a line", async () => {
    const input = new PassThrough();
    const out = collect();
    const p = promptPassword("pw: ", input, out.stream);
    input.end();
    await expect(p).rejects.toThrow(/password/i);
  });
});

describe("readAllStdin", () => {
  it("reads the full stream as UTF-8", async () => {
    const input = new PassThrough();
    const p = readAllStdin(input);
    input.write("line1\n");
    input.write("line2");
    input.end();
    expect(await p).toBe("line1\nline2");
  });

  it("returns empty string for empty stream", async () => {
    const input = new PassThrough();
    const p = readAllStdin(input);
    input.end();
    expect(await p).toBe("");
  });
});
