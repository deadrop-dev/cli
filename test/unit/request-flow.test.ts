import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import {
  createRequestKeys,
  fingerprintFromPrivate,
  fingerprintOfPublic,
  claimProofFromPrivate,
  openResponse,
  sealForRequest,
} from "../../src/lib/request-flow.js";
import { derivePublicKeyB64 } from "@deadrop/crypto";
import { CliError } from "../../src/lib/errors.js";

interface RequestVector {
  name: string;
  requester_public_key_b64: string;
  requester_private_key_pkcs8_b64: string;
  responder_public_key_b64: string;
  hkdf_salt_b64: string;
  wrap_iv_b64: string;
  wrapped_key_b64: string;
  iv_b64: string;
  plaintext: string;
  ciphertext_b64: string;
  claim_proof: string;
  requester_fingerprint: string;
}

const vectors = JSON.parse(
  readFileSync(
    new URL("../../node_modules/@deadrop/crypto/test-vectors.json", import.meta.url),
    "utf8",
  ),
) as { request_vectors: RequestVector[] };

describe("published @deadrop/crypto request vectors through CLI plumbing", () => {
  it("ships at least one request vector", () => {
    expect(vectors.request_vectors.length).toBeGreaterThanOrEqual(1);
  });

  for (const v of vectors.request_vectors) {
    it(`${v.name}: claim proof, fingerprint, and decryption match the vector`, async () => {
      expect(await claimProofFromPrivate(v.requester_private_key_pkcs8_b64)).toBe(v.claim_proof);
      expect(await fingerprintOfPublic(v.requester_public_key_b64)).toBe(v.requester_fingerprint);
      expect(await fingerprintFromPrivate(v.requester_private_key_pkcs8_b64)).toBe(
        v.requester_fingerprint,
      );
      expect(await derivePublicKeyB64(v.requester_private_key_pkcs8_b64)).toBe(
        v.requester_public_key_b64,
      );

      const plaintext = await openResponse(
        {
          encrypted: v.ciphertext_b64,
          iv: v.iv_b64,
          wrappedKey: v.wrapped_key_b64,
          wrapIv: v.wrap_iv_b64,
          hkdfSalt: v.hkdf_salt_b64,
          responderPublicKey: v.responder_public_key_b64,
        },
        v.requester_private_key_pkcs8_b64,
      );
      expect(plaintext).toBe(v.plaintext);
    });
  }
});

describe("request-flow round-trip (fresh keys)", () => {
  it("seal → open round-trips unicode byte-exact", async () => {
    const keys = await createRequestKeys();
    const secret = "jenkins-token=ghp_Xy7… norsk æøå 🔑\nline two";
    const blob = await sealForRequest(secret, keys.publicKeyB64);
    expect(Object.keys(blob).sort()).toEqual([
      "encrypted",
      "hkdfSalt",
      "iv",
      "responderPublicKey",
      "wrapIv",
      "wrappedKey",
    ]);
    expect(await openResponse(blob, keys.privateKeyB64)).toBe(secret);
  });

  it("a different private key cannot open the response", async () => {
    const keys = await createRequestKeys();
    const other = await createRequestKeys();
    const blob = await sealForRequest("sealed", keys.publicKeyB64);
    await expect(openResponse(blob, other.privateKeyB64)).rejects.toThrow(CliError);
  });

  it("corrupted private key fails locally with a user error", async () => {
    // claimProof is a hash of the fragment STRING — it cannot detect
    // corruption; the PKCS8 import inside the fingerprint derivation can,
    // and runClaim computes it before any network I/O.
    await expect(fingerprintFromPrivate("notakey")).rejects.toThrow(/corrupted/);
    await expect(fingerprintFromPrivate("")).rejects.toThrow(CliError);
  });

  it("malformed public key is refused before encryption", async () => {
    await expect(sealForRequest("x", "garbage")).rejects.toThrow(CliError);
  });
});
