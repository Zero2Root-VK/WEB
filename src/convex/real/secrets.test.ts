import { describe, expect, it } from "bun:test";
import {
  decryptSecret,
  deriveKey,
  encryptSecret,
  isEncryptedSecret,
  maskSecret,
  requireSecretKey,
} from "./secrets";

const KEY_MATERIAL = "correct-horse-battery-staple-operator-key";
const SECRET = "session=4f8a9c1e-77d2-4b9a-9f6c-1d2e3f4a5b6c; HttpOnly";

async function keyFor(material = KEY_MATERIAL): Promise<CryptoKey> {
  return deriveKey(material);
}

describe("credential encryption", () => {
  it("round-trips a credential", async () => {
    const key = await keyFor();
    const payload = await encryptSecret(SECRET, key);
    expect(await decryptSecret(payload, key)).toBe(SECRET);
  });

  it("never embeds the plaintext in the stored record", async () => {
    const key = await keyFor();
    const payload = await encryptSecret(SECRET, key);
    expect(payload).not.toContain(SECRET);
    expect(payload).not.toContain("4f8a9c1e");
    expect(payload.startsWith("wabve1.")).toBe(true);
  });

  it("uses a fresh IV so identical credentials never produce identical records", async () => {
    const key = await keyFor();
    const first = await encryptSecret(SECRET, key);
    const second = await encryptSecret(SECRET, key);
    expect(first).not.toBe(second);
    // Deterministic ciphertext would confirm to anyone holding both records
    // that the same credential is in use.
    expect(first.split(".")[2]).not.toBe(second.split(".")[2]);
  });

  it("derives a repeatable key so decryption works across invocations", async () => {
    const payload = await encryptSecret(SECRET, await keyFor());
    const later = await keyFor();
    expect(await decryptSecret(payload, later)).toBe(SECRET);
  });

  it("rejects an empty credential rather than storing a blank record", async () => {
    const key = await keyFor();
    await expect(encryptSecret("", key)).rejects.toThrow(/empty credential/);
  });
});

describe("tamper and access resistance", () => {
  it("refuses a tampered record", async () => {
    const key = await keyFor();
    const payload = await encryptSecret(SECRET, key);
    const [version, iv, ciphertext] = payload.split(".");
    const tampered = `${version}.${ciphertext}.${iv}`;
    await expect(decryptSecret(tampered, key)).rejects.toThrow(
      "credential could not be decrypted",
    );
  });

  it("refuses the wrong key", async () => {
    const payload = await encryptSecret(SECRET, await keyFor());
    const other = await keyFor("a-completely-different-operator-key");
    await expect(decryptSecret(payload, other)).rejects.toThrow(
      "credential could not be decrypted",
    );
  });

  it("refuses a malformed record", async () => {
    const key = await keyFor();
    await expect(decryptSecret("not-a-record", key)).rejects.toThrow(
      "not in a recognised format",
    );
    await expect(decryptSecret("wabve2.aaaa.bbbb", key)).rejects.toThrow(
      "not in a recognised format",
    );
  });

  it("never echoes the plaintext or key material in a failure", async () => {
    const key = await keyFor(KEY_MATERIAL);
    const payload = await encryptSecret(SECRET, key);
    const other = await keyFor("another-operator-key-that-is-long-enough");
    try {
      await decryptSecret(payload, other);
      throw new Error("expected decryption to fail");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      expect(message).not.toContain(SECRET);
      expect(message).not.toContain(KEY_MATERIAL);
      expect(message).not.toContain("OperationError");
    }
  });

  it("requires meaningful key material", async () => {
    await expect(deriveKey("short")).rejects.toThrow(/at least 16 characters/);
  });
});

describe("environment key handling", () => {
  it("produces an actionable error when the key is missing", () => {
    expect(() => requireSecretKey({})).toThrow(/WABVE_SECRETS_KEY is not set/);
    expect(() => requireSecretKey({})).toThrow(/Keys tab/);
  });

  it("rejects key material that is too short", () => {
    expect(() => requireSecretKey({ WABVE_SECRETS_KEY: "tooshort" })).toThrow(
      /at least 16 characters/,
    );
  });

  it("derives a usable key from the environment", async () => {
    const key = await requireSecretKey({ WABVE_SECRETS_KEY: KEY_MATERIAL });
    const payload = await encryptSecret(SECRET, key);
    expect(await decryptSecret(payload, key)).toBe(SECRET);
  });
});

describe("record recognition", () => {
  it("accepts a genuine record", async () => {
    const payload = await encryptSecret(SECRET, await keyFor());
    expect(isEncryptedSecret(payload)).toBe(true);
  });

  it("rejects anything else", () => {
    expect(isEncryptedSecret("")).toBe(false);
    expect(isEncryptedSecret("plaintext")).toBe(false);
    expect(isEncryptedSecret("wabve1.aa.bb")).toBe(false);
    expect(isEncryptedSecret("wabve1.aaaa.bbbb.cccc")).toBe(false);
  });
});

describe("display masking", () => {
  it("reveals nothing about a short credential", () => {
    expect(maskSecret("abc")).toBe("••••••");
    expect(maskSecret("0123456789abcde")).toBe("••••••");
  });

  it("keeps two characters so operators can tell keys apart", () => {
    expect(maskSecret("tok_live_0123456789abcdef")).toBe("to••••••ef");
  });

  it("returns nothing for an empty value", () => {
    expect(maskSecret("")).toBe("");
  });
});
