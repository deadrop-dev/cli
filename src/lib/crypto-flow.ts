import {
  base64UrlToBytes,
  computeKeyHash,
  computeKeyHashFromB64,
  decrypt,
  deriveKeyWithPassword,
  deserializePayload,
  encrypt,
  exportKey,
  generateKey,
  importKey,
  serializePayload,
} from "@deadrop/crypto";
import { userError } from "./errors.js";
import type { Kdf } from "./url.js";

export interface SealedSecret {
  /** URL key (goes in the fragment) — NOT the derived key for password secrets */
  keyB64: string;
  /** base64url(ciphertext || GCM tag) */
  encrypted: string;
  /** base64url(12-byte IV) */
  iv: string;
  /** SHA-256 hash of the ENCRYPTION key (derived key when password-protected) */
  keyHash: string;
  passwordProtected: boolean;
}

/**
 * Encrypt a secret per SPEC v2.0. With a password, the encryption key is
 * PBKDF2-derived from the NFC-normalized password salted with the raw URL key
 * bytes, and keyHash is computed from the DERIVED key.
 */
export async function sealSecret(
  plaintext: string,
  options: { password?: string } = {},
): Promise<SealedSecret> {
  const key = await generateKey();
  const keyB64 = await exportKey(key);

  let encryptionKey = key;
  let keyHash: string;
  if (options.password !== undefined) {
    const nfcPassword = options.password.normalize("NFC");
    encryptionKey = await deriveKeyWithPassword(base64UrlToBytes(keyB64), nfcPassword);
    keyHash = await computeKeyHash(encryptionKey);
  } else {
    keyHash = await computeKeyHashFromB64(keyB64);
  }

  const payload = serializePayload(await encrypt(plaintext, encryptionKey));
  return {
    keyB64,
    encrypted: payload.ciphertext,
    iv: payload.iv,
    keyHash,
    passwordProtected: options.password !== undefined,
  };
}

/** Decrypt a retrieved blob. Throws CliError(1) on auth failure. */
export async function openSecret(
  blob: { encrypted: string; iv: string },
  key: CryptoKey,
): Promise<string> {
  try {
    return await decrypt(
      deserializePayload({ ciphertext: blob.encrypted, iv: blob.iv }),
      key,
    );
  } catch {
    throw userError(
      "Failed to decrypt the secret — the key or password does not match the ciphertext.",
    );
  }
}

export interface ReceiveCandidate {
  key: CryptoKey;
  keyHash: string;
}

/**
 * Build the ordered list of decryption candidates for the receive path.
 *
 * - kdf "none": single candidate from the URL key.
 * - kdf "pbkdf2": NFC-normalized password first (SPEC 2.0 normative), raw
 *   un-normalized password as a fallback for legacy pre-2.0 secrets — only
 *   when the two differ. The server's key-hash gate returns 403 WITHOUT
 *   burning on a mismatch, so trying candidates sequentially is safe.
 */
export async function receiveCandidates(
  keyB64: string,
  kdf: Kdf,
  password?: string,
): Promise<ReceiveCandidate[]> {
  if (kdf === "none") {
    return [
      { key: await importKey(keyB64), keyHash: await computeKeyHashFromB64(keyB64) },
    ];
  }

  if (password === undefined) {
    throw userError("This secret is password-protected — a password is required.");
  }

  const urlKeyRaw = base64UrlToBytes(keyB64);
  const nfc = password.normalize("NFC");
  const candidates: ReceiveCandidate[] = [];

  const nfcKey = await deriveKeyWithPassword(urlKeyRaw, nfc);
  candidates.push({ key: nfcKey, keyHash: await computeKeyHash(nfcKey) });

  if (nfc !== password) {
    const rawKey = await deriveKeyWithPassword(urlKeyRaw, password);
    candidates.push({ key: rawKey, keyHash: await computeKeyHash(rawKey) });
  }

  return candidates;
}
