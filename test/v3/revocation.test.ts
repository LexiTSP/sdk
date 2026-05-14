import { describe, it, expect } from "vitest";
import { checkRevocation, pruneRevoked } from "../../src/v3/revocation";
import type { RevokedEntry } from "../../src/v3/manifest-types";

const revoked: RevokedEntry[] = [
  { id: "i1", revokedAt: "2026-04-15T00:00:00Z", reason: "key compromise" },
  { id: "i2", revokedAt: "2026-03-01T00:00:00Z", reason: "operator request" },
];

describe("checkRevocation()", () => {
  it("returns ok when instanceId not in revoked list", () => {
    expect(checkRevocation("i999", "2026-04-30T00:00:00Z", revoked).status).toBe("not-revoked");
  });

  it("returns ok when envelope predates the revocation", () => {
    expect(checkRevocation("i1", "2026-04-10T00:00:00Z", revoked).status).toBe("predates-revocation");
  });

  it("returns failed when envelope produced after revocation", () => {
    const r = checkRevocation("i1", "2026-04-20T00:00:00Z", revoked);
    expect(r.status).toBe("revoked");
    expect(r.detail).toMatch(/key compromise/);
  });

  it("treats envelope at exact revocation time as revoked", () => {
    expect(checkRevocation("i1", "2026-04-15T00:00:00Z", revoked).status).toBe("revoked");
  });
});

describe("pruneRevoked()", () => {
  it("removes entries old enough that no envelope could reference them", () => {
    const pruned = pruneRevoked(revoked, { now: "2026-05-01T00:00:00Z", acceptableAgeSeconds: 86400, graceDays: 7 });
    expect(pruned).toHaveLength(0);
  });

  it("keeps recent revocations", () => {
    const pruned = pruneRevoked(revoked, { now: "2026-04-20T00:00:00Z", acceptableAgeSeconds: 86400, graceDays: 7 });
    expect(pruned.map((r) => r.id)).toEqual(["i1"]);
  });
});
