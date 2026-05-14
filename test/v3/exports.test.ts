import { describe, it, expect } from "vitest";

describe("v3 subpath exports", () => {
  it("exports the public surface", async () => {
    const v3 = await import("../../src/v3/index");
    expect(v3.TSP_V3_VERSION).toBe("3.0");
    expect(typeof v3.wrap).toBe("function");
    expect(typeof v3.verifyLocal).toBe("function");
    expect(typeof v3.canonicalize).toBe("function");
    expect(typeof v3.generateKeyPair).toBe("function");
  });
});
