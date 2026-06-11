import { bytesToBase64Url } from "@deadrop/crypto";

/** Generate a client-side secret id: 24 random bytes → 32-char base64url (SPEC §4). */
export function generateId(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}
