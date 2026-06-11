import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import {
  sealSecret,
  openSecret,
  receiveCandidates,
} from "../../src/lib/crypto-flow.js";
import {
  importKey,
  deriveKeyWithPassword,
  base64UrlToBytes,
  computeKeyHashFromB64,
  computeKeyHash,
  exportKey,
  encrypt,
  serializePayload,
} from "@deadrop/crypto";

interface Vectors {
  vectors: {
    name: string;
    key_b64: string;
    iv_b64: string;
    plaintext: string;
    ciphertext_b64: string;
    key_hash: string;
  }[];
  password_vectors: {
    name: string;
    url_key_b64: string;
    password: string;
    derived_key_b64: string;
    derived_key_hash: string;
    iv_b64: string;
    plaintext: string;
    ciphertext_b64: string;
  }[];
}

const vectors: Vectors = JSON.parse(
  readFileSync(
    new URL("../../node_modules/@deadrop/crypto/test-vectors.json", import.meta.url),
    "utf8",
  ),
);

describe("published @deadrop/crypto test vectors through CLI plumbing", () => {
  it("decrypts every basic vector via openSecret", async () => {
    for (const v of vectors.vectors) {
      const plaintext = await openSecret(
        { encrypted: v.ciphertext_b64, iv: v.iv_b64 },
        await importKey(v.key_b64),
      );
      expect(plaintext, v.name).toBe(v.plaintext);
    }
  });

  it("computes matching key hashes for every basic vector", async () => {
    for (const v of vectors.vectors) {
      expect(await computeKeyHashFromB64(v.key_b64), v.name).toBe(v.key_hash);
    }
  });

  it("derives matching keys + hashes + plaintext for every password vector", async () => {
    for (const v of vectors.password_vectors) {
      const derived = await deriveKeyWithPassword(
        base64UrlToBytes(v.url_key_b64),
        v.password,
      );
      expect(await exportKey(derived), v.name).toBe(v.derived_key_b64);
      expect(await computeKeyHash(derived), v.name).toBe(v.derived_key_hash);
      const plaintext = await openSecret(
        { encrypted: v.ciphertext_b64, iv: v.iv_b64 },
        derived,
      );
      expect(plaintext, v.name).toBe(v.plaintext);
    }
  });
});

describe("sealSecret", () => {
  it("round-trips a plain secret", async () => {
    const sealed = await sealSecret("top secret value");
    expect(sealed.passwordProtected).toBe(false);
    expect(sealed.keyB64).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(sealed.keyHash).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(sealed.keyHash).toBe(await computeKeyHashFromB64(sealed.keyB64));

    const plaintext = await openSecret(
      { encrypted: sealed.encrypted, iv: sealed.iv },
      await importKey(sealed.keyB64),
    );
    expect(plaintext).toBe("top secret value");
  });

  it("round-trips a password-protected secret; keyHash is of the DERIVED key", async () => {
    const sealed = await sealSecret("guarded", { password: "hunter2" });
    expect(sealed.passwordProtected).toBe(true);
    // keyHash must NOT be the URL key hash
    expect(sealed.keyHash).not.toBe(await computeKeyHashFromB64(sealed.keyB64));

    const derived = await deriveKeyWithPassword(
      base64UrlToBytes(sealed.keyB64),
      "hunter2",
    );
    expect(await computeKeyHash(derived)).toBe(sealed.keyHash);
    const plaintext = await openSecret(
      { encrypted: sealed.encrypted, iv: sealed.iv },
      derived,
    );
    expect(plaintext).toBe("guarded");
  });

  it("NFC-normalizes the password on the encrypt path (SPEC 2.0)", async () => {
    const decomposed = "cafe\u0301"; // NFD: e + combining acute
    const composed = "caf\u00e9"; // NFC: precomposed e-acute
    const sealed = await sealSecret("nfc", { password: decomposed });
    const derivedComposed = await deriveKeyWithPassword(
      base64UrlToBytes(sealed.keyB64),
      composed,
    );
    expect(await computeKeyHash(derivedComposed)).toBe(sealed.keyHash);
  });
});

describe("receiveCandidates (decrypt path, NFC-first with raw fallback)", () => {
  it("returns one candidate for plain secrets", async () => {
    const sealed = await sealSecret("x");
    const cands = await receiveCandidates(sealed.keyB64, "none");
    expect(cands).toHaveLength(1);
    expect(cands[0]!.keyHash).toBe(sealed.keyHash);
  });

  it("returns NFC candidate first, raw fallback second for non-NFC passwords", async () => {
    const decomposed = "cafe\u0301";
    const cands = await receiveCandidates("AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "pbkdf2", decomposed);
    expect(cands).toHaveLength(2);
    // first = NFC-normalized, second = raw legacy
    const urlKeyRaw = base64UrlToBytes("AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    const nfc = await deriveKeyWithPassword(urlKeyRaw, decomposed.normalize("NFC"));
    const raw = await deriveKeyWithPassword(urlKeyRaw, decomposed);
    expect(cands[0]!.keyHash).toBe(await computeKeyHash(nfc));
    expect(cands[1]!.keyHash).toBe(await computeKeyHash(raw));
  });

  it("returns a single candidate for ASCII passwords (NFC is a no-op)", async () => {
    const cands = await receiveCandidates("AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "pbkdf2", "hunter2");
    expect(cands).toHaveLength(1);
  });

  it("raw fallback candidate decrypts legacy (pre-2.0, non-NFC) secrets", async () => {
    // Simulate a pre-2.0 client: derive with the RAW decomposed password.
    const decomposed = "cafe\u0301";
    const urlKeyB64 = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const legacyKey = await deriveKeyWithPassword(base64UrlToBytes(urlKeyB64), decomposed);
    const payload = serializePayload(await encrypt("legacy secret", legacyKey));

    const cands = await receiveCandidates(urlKeyB64, "pbkdf2", decomposed);
    const legacyHash = await computeKeyHash(legacyKey);
    const match = cands.find((c) => c.keyHash === legacyHash);
    expect(match).toBeDefined();
    const plaintext = await openSecret(
      { encrypted: payload.ciphertext, iv: payload.iv },
      match!.key,
    );
    expect(plaintext).toBe("legacy secret");
  });

  it("throws a wrong-key style error when decrypting with a wrong key", async () => {
    const sealed = await sealSecret("x");
    const wrong = await importKey("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    await expect(
      openSecret({ encrypted: sealed.encrypted, iv: sealed.iv }, wrong),
    ).rejects.toThrow(/decrypt/i);
  });
});
