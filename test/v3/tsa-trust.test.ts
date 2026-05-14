import { describe, it, expect } from "vitest";
import {
  fingerprintCert,
  isTrustedTsaCert,
  DEFAULT_TRUSTED_TSAS,
  type TrustedTsa,
} from "../../src/v3/tsa-trust";

describe("tsa-trust", () => {
  it("default trust list is empty (charter §6)", () => {
    expect(DEFAULT_TRUSTED_TSAS).toEqual([]);
  });

  it("fingerprintCert produces 64-hex SHA-256", async () => {
    const certBytes = new Uint8Array([1, 2, 3, 4, 5]);
    const fp = await fingerprintCert(certBytes);
    expect(fp).toMatch(/^[a-f0-9]{64}$/);
    // Stable: same input → same output
    const fp2 = await fingerprintCert(certBytes);
    expect(fp).toBe(fp2);
  });

  it("isTrustedTsaCert returns false on empty trust list", async () => {
    const result = await isTrustedTsaCert(new Uint8Array([1, 2, 3]), []);
    expect(result.trusted).toBe(false);
  });

  it("isTrustedTsaCert matches a configured fingerprint", async () => {
    const certBytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const fp = await fingerprintCert(certBytes);
    const trustList: TrustedTsa[] = [
      { name: "Test TSA", certFingerprintSha256: fp },
    ];
    const result = await isTrustedTsaCert(certBytes, trustList);
    expect(result.trusted).toBe(true);
    expect(result.matched?.name).toBe("Test TSA");
  });

  it("isTrustedTsaCert rejects unknown cert against non-empty list", async () => {
    const trustList: TrustedTsa[] = [
      { name: "Other", certFingerprintSha256: "0".repeat(64) },
    ];
    const result = await isTrustedTsaCert(new Uint8Array([1, 2, 3]), trustList);
    expect(result.trusted).toBe(false);
  });
});
