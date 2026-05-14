import { describe, it, expect } from "vitest";
import { isCertValidAt } from "../../src/v3/cert";
import type { InstanceCertEntry } from "../../src/v3/manifest-types";

const cert: InstanceCertEntry = {
  id: "i1",
  publicKey: { kty: "OKP", crv: "Ed25519", x: "test" },
  validFrom: "2026-04-01T00:00:00Z",
  validUntil: "2026-05-01T00:00:00Z",
  rootSignature: "test",
};

describe("isCertValidAt()", () => {
  it("returns valid for tsTime exactly at validFrom", () => {
    expect(isCertValidAt(cert, "2026-04-01T00:00:00Z").valid).toBe(true);
  });

  it("returns valid for tsTime exactly at validUntil", () => {
    expect(isCertValidAt(cert, "2026-05-01T00:00:00Z").valid).toBe(true);
  });

  it("returns invalid for tsTime 1ms before validFrom", () => {
    const r = isCertValidAt(cert, "2026-03-31T23:59:59.999Z");
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/before validFrom/);
  });

  it("returns invalid for tsTime 1ms after validUntil", () => {
    const r = isCertValidAt(cert, "2026-05-01T00:00:00.001Z");
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/after validUntil/);
  });

  it("returns invalid for unparseable tsTime", () => {
    expect(isCertValidAt(cert, "not-a-date").valid).toBe(false);
  });
});
