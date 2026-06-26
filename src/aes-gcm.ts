import { bytesToBase64, base64ToBytes } from "./base64.ts";

export interface EncryptionResult {
  /** `iv.ciphertext`, both base64. The 128-bit GCM auth tag is appended to the ciphertext. */
  encryptedBlob: string;
  /** Raw 256-bit AES key, base64. Never transmitted to a server in VaultPass. */
  key: string;
}

/**
 * Encrypts a UTF-8 string with AES-256-GCM.
 *
 * - Fresh 256-bit key per call (`crypto.subtle.generateKey`).
 * - Fresh random 96-bit IV per call (NIST SP 800-38D recommended length).
 * - GCM authentication tag retained — any ciphertext tampering fails decryption.
 *
 * The plaintext never leaves the caller's environment.
 */
export async function encryptSeedPhrase(seedPhrase: string): Promise<EncryptionResult> {
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(seedPhrase),
  );

  const exportedKey = await crypto.subtle.exportKey("raw", key);

  const encryptedBlob = bytesToBase64(iv) + "." + bytesToBase64(new Uint8Array(encrypted));
  const keyB64 = bytesToBase64(new Uint8Array(exportedKey));

  return { encryptedBlob, key: keyB64 };
}

/**
 * Decrypts an `iv.ciphertext` blob with a base64-encoded AES-256-GCM key.
 * Throws if the blob is malformed or the auth tag does not verify.
 */
export async function decryptSeedPhrase(encryptedBlob: string, keyB64: string): Promise<string> {
  const parts = encryptedBlob.split(".");
  if (parts.length !== 2) {
    throw new Error("Invalid encrypted blob format");
  }

  const [ivB64, ciphertextB64] = parts;

  const iv = base64ToBytes(ivB64);
  const ciphertext = base64ToBytes(ciphertextB64);
  const rawKey = base64ToBytes(keyB64);

  const key = await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );

  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);

  return new TextDecoder().decode(decrypted);
}
