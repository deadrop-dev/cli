import { describe, it, expect } from "vitest";
import { generateId } from "../../src/lib/id.js";

describe("generateId", () => {
  it("produces 32-char base64url ids (24 random bytes)", () => {
    const id = generateId();
    expect(id).toHaveLength(32);
    expect(id).toMatch(/^[A-Za-z0-9_-]{32}$/);
  });

  it("produces unique ids", () => {
    const seen = new Set(Array.from({ length: 100 }, () => generateId()));
    expect(seen.size).toBe(100);
  });
});
