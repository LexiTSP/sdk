import { describe, it, expect } from "vitest";
import { generateKeyPair, sign, verify, exportPublicKeyJwk } from "../../src/v3/crypto";
import fc from "fast-check";

describe("Ed25519 primitives", () => {
  it("generateKeyPair produces a usable Ed25519 keypair", async () => {
    const { publicKey, privateKey } = await generateKeyPair();
    expect(publicKey).toBeDefined();
    expect(privateKey).toBeDefined();
    const jwk = await exportPublicKeyJwk(publicKey);
    expect(jwk.kty).toBe("OKP");
    expect(jwk.crv).toBe("Ed25519");
    expect(typeof jwk.x).toBe("string");
  });

  it("sign + verify round-trips correctly", async () => {
    const kp = await generateKeyPair();
    const data = new TextEncoder().encode("hello world");
    const sig = await sign(kp.privateKey, data);
    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig.length).toBe(64);
    const valid = await verify(kp.publicKey, sig, data);
    expect(valid).toBe(true);
  });

  it("verify rejects tampered data", async () => {
    const kp = await generateKeyPair();
    const data = new TextEncoder().encode("hello world");
    const sig = await sign(kp.privateKey, data);
    const tampered = new TextEncoder().encode("hello WORLD");
    const valid = await verify(kp.publicKey, sig, tampered);
    expect(valid).toBe(false);
  });

  it("verify rejects signature from different key", async () => {
    const kp1 = await generateKeyPair();
    const kp2 = await generateKeyPair();
    const data = new TextEncoder().encode("hello");
    const sig = await sign(kp1.privateKey, data);
    const valid = await verify(kp2.publicKey, sig, data);
    expect(valid).toBe(false);
  });
});

describe("Ed25519 properties", () => {
  it("any payload signed by a key verifies with that key", async () => {
    const kp = await generateKeyPair();
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ minLength: 0, maxLength: 1024 }),
        async (data) => {
          const sig = await sign(kp.privateKey, data);
          return await verify(kp.publicKey, sig, data);
        }
      ),
      { numRuns: 50 }
    );
  });
});
