/**
 * WABVE — credential encryption.
 *
 * Identity credentials (session cookies, bearer tokens, passwords) are the
 * most damaging thing this product handles: a leak here hands an attacker a
 * live session on the customer's own target. So they are never stored in
 * plaintext and never returned by a query — this module encrypts them with
 * AES-256-GCM under a key derived from the operator's environment, and the
 * only value the UI ever receives is a mask.
 *
 * GCM is authenticated, so a tampered record fails to decrypt rather than
 * returning corrupted bytes; every failure is reported without echoing the
 * plaintext, the key material, or the underlying WebCrypto message.
 */

const VERSION = "wabve1";
const HKDF_SALT = "wabve.v1.identity-secrets";
const HKDF_INFO = "identity-credential";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Derive the AES-256 key from the operator's secret. HKDF means any
 * high-entropy operator string works — they do not need to hand us exactly 32
 * raw bytes — while the salt binds it to this specific purpose so the same
 * passphrase cannot be reused across contexts by accident.
 */
export async function deriveKey(material: string): Promise<CryptoKey> {
  if (!material || material.trim().length < 16) {
    throw new Error("secret key material must be at least 16 characters");
  }
  const base = await crypto.subtle.importKey("raw", encoder.encode(material), "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: encoder.encode(HKDF_SALT), info: encoder.encode(HKDF_INFO) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptSecret(plaintext: string, key: CryptoKey): Promise<string> {
  if (plaintext.length === 0) throw new Error("refusing to encrypt an empty credential");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(plaintext)),
  );
  return [VERSION, toBase64(iv), toBase64(ciphertext)].join(".");
}

export async function decryptSecret(payload: string, key: CryptoKey): Promise<string> {
  const parts = payload.split(".");
  if (parts.length !== 3 || parts[0] !== VERSION) {
    throw new Error("credential record is not in a recognised format");
  }
  try {
    const iv = fromBase64(parts[1]);
    const ciphertext = fromBase64(parts[2]);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext,
    );
    return decoder.decode(plaintext);
  } catch {
    // Deliberately opaque: no plaintext, no key, no WebCrypto detail.
    throw new Error("credential could not be decrypted");
  }
}

export function isEncryptedSecret(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 3 || parts[0] !== VERSION) return false;
  try {
    fromBase64(parts[1]);
    fromBase64(parts[2]);
    return parts[1].length >= 16 && parts[2].length >= 8;
  } catch {
    return false;
  }
}

/**
 * A stable, safe string for display. Two characters of a long token are kept
 * so an operator can tell two keys apart; short values reveal nothing.
 */
export function maskSecret(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0) return "";
  if (trimmed.length < 16) return "••••••";
  return `${trimmed.slice(0, 2)}••••••${trimmed.slice(-2)}`;
}

/** Read the key from the environment, with an actionable failure message. */
export function requireSecretKey(
  env: Record<string, string | undefined>,
): Promise<CryptoKey> {
  const material = env.WABVE_SECRETS_KEY;
  if (!material) {
    throw new Error(
      "WABVE_SECRETS_KEY is not set — configure it in the project's Keys tab before storing credentials",
    );
  }
  return deriveKey(material);
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const bytes: Uint8Array<ArrayBuffer> = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
