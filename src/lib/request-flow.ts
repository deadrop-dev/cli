import {
  computeClaimProof,
  computeFingerprint,
  decryptResponse,
  derivePublicKeyB64,
  encryptForRequest,
  generateRequestKeyPair,
} from "@deadrop/crypto";
import { userError } from "./errors.js";

/**
 * Request flow per SPEC 2.1 §9: the requester publishes an ephemeral ECDH
 * P-256 public key; the responder hybrid-encrypts to it (fresh AES data key,
 * ECDH + HKDF-derived wrapping key); the requester proves claim rights with
 * a hash of the private key and burns the response on read.
 */

export interface RequestKeys {
  /** Raw 65-byte P-256 public key, base64url — goes to the server. */
  publicKeyB64: string;
  /** PKCS8 private key, base64url — claim-link fragment ONLY, never sent. */
  privateKeyB64: string;
  /** base64url(SHA-256(privateKeyB64))[:22] — the server's claim gate. */
  claimProof: string;
  /** First 8 chars of base64url(SHA-256(raw public key)) — §9.4 MITM honesty. */
  fingerprint: string;
}

export async function createRequestKeys(): Promise<RequestKeys> {
  const { publicKeyB64, privateKeyB64 } = await generateRequestKeyPair();
  return {
    publicKeyB64,
    privateKeyB64,
    claimProof: await computeClaimProof(privateKeyB64),
    fingerprint: await computeFingerprint(publicKeyB64),
  };
}

/** §9 response wire fields — exact SPEC names. */
export interface ResponseBlob {
  encrypted: string;
  iv: string;
  wrappedKey: string;
  wrapIv: string;
  hkdfSalt: string;
  responderPublicKey: string;
}

/** Encrypt a secret to a requester's public key (responder side). */
export async function sealForRequest(
  plaintext: string,
  requesterPublicKeyB64: string,
): Promise<ResponseBlob> {
  try {
    return await encryptForRequest(plaintext, requesterPublicKeyB64);
  } catch {
    throw userError(
      "Could not encrypt to the requester's key — the request link may be corrupted.",
    );
  }
}

/** Decrypt a claimed response with the fragment private key (requester side). */
export async function openResponse(
  blob: ResponseBlob,
  privateKeyB64: string,
): Promise<string> {
  try {
    return await decryptResponse(blob, privateKeyB64);
  } catch {
    throw userError(
      "Failed to decrypt the response — the claim key does not match the ciphertext.",
    );
  }
}

/** Claim proof from the fragment private key. Throws on a corrupted key. */
export async function claimProofFromPrivate(privateKeyB64: string): Promise<string> {
  try {
    return await computeClaimProof(privateKeyB64);
  } catch {
    throw userError("Invalid claim link — the key fragment is corrupted.");
  }
}

/**
 * Fingerprint recovered from the private key (claim side, §9.4: both ends
 * must be able to compare the same code).
 */
export async function fingerprintFromPrivate(privateKeyB64: string): Promise<string> {
  try {
    return await computeFingerprint(await derivePublicKeyB64(privateKeyB64));
  } catch {
    throw userError("Invalid claim link — the key fragment is corrupted.");
  }
}

/** Fingerprint of a requester public key (fulfill side, §9.4). */
export async function fingerprintOfPublic(publicKeyB64: string): Promise<string> {
  try {
    return await computeFingerprint(publicKeyB64);
  } catch {
    throw userError("The request's public key is malformed — refusing to encrypt to it.");
  }
}
