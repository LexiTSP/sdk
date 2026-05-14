import { describe, it, expect, vi } from "vitest";
import { verifyDane } from "../../src/v3/dane";
import { canonicalize } from "../../src/v3/canonical";
import { sha256Hex } from "../../src/v3/canonical-hash";
import type { JwkEd25519Public } from "../../src/v3/crypto";

const rootKey: JwkEd25519Public = { kty: "OKP", crv: "Ed25519", x: "test-pubkey-x" };

describe("verifyDane", () => {
  it("accepts AD=true with matching rootKeyHash", async () => {
    const expectedHash = await sha256Hex(canonicalize(rootKey));
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          Status: 0,
          AD: true,
          Answer: [
            {
              name: "_tsp.test.example",
              type: 16,
              data: `"v=tsp1; rootKeyHash=sha256-${expectedHash}; manifest=https://test.example/keys.json"`,
            },
          ],
        }),
        { status: 200 }
      )
    );
    const result = await verifyDane("test.example", rootKey, { fetch: fetchMock });
    expect(result.valid).toBe(true);
    expect(result.manifestUrlFromDns).toBe("https://test.example/keys.json");
  });

  it("rejects AD=false", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({ Status: 0, AD: false, Answer: [] }),
        { status: 200 }
      )
    );
    const result = await verifyDane("test.example", rootKey, { fetch: fetchMock });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/DNSSEC/i);
  });

  it("rejects when rootKeyHash mismatches", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          Status: 0,
          AD: true,
          Answer: [
            {
              name: "_tsp.test.example",
              type: 16,
              data: `"v=tsp1; rootKeyHash=sha256-${"f".repeat(64)}"`,
            },
          ],
        }),
        { status: 200 }
      )
    );
    const result = await verifyDane("test.example", rootKey, { fetch: fetchMock });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/does not match/i);
  });

  it("rejects when no v=tsp1 record found", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          Status: 0,
          AD: true,
          Answer: [{ name: "_tsp.test.example", type: 16, data: '"unrelated=stuff"' }],
        }),
        { status: 200 }
      )
    );
    const result = await verifyDane("test.example", rootKey, { fetch: fetchMock });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/v=tsp1/i);
  });

  it("rejects on network error", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("ENETUNREACH"));
    const result = await verifyDane("test.example", rootKey, { fetch: fetchMock });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/DoH/i);
  });
});
