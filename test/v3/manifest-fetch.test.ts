import { describe, it, expect, beforeEach, vi } from "vitest";
import { fetchManifest, clearManifestCache } from "../../src/v3/manifest-fetch";
import type { TrustManifest } from "../../src/v3/manifest-types";

const manifest: TrustManifest = {
  tsp: "3.0",
  organization: { name: "T", domain: "t.example" },
  rootKey: { kty: "OKP", crv: "Ed25519", x: "x" },
  instances: [],
  revoked: [],
  sequence: 1,
  issuedAt: "2026-04-30T12:00:00Z",
  acceptableAge: { seconds: 86400 },
  rootSignatureOverManifest: "sig",
};

beforeEach(() => clearManifestCache());

describe("fetchManifest()", () => {
  it("performs initial fetch and caches", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(manifest), {
        status: 200,
        headers: { "content-type": "application/json", etag: '"v1"' },
      })
    );
    const result = await fetchManifest("https://t.example/.well-known/tsp/keys.json", { fetch: fetchMock });
    expect(result.manifest.organization.domain).toBe("t.example");
    expect(result.fromCache).toBe(false);
    expect(result.etag).toBe('"v1"');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("returns cached result on second call within TTL", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(manifest), { status: 200, headers: { etag: '"v1"' } })
    );
    const url = "https://t.example/.well-known/tsp/keys.json";
    await fetchManifest(url, { fetch: fetchMock });
    const second = await fetchManifest(url, { fetch: fetchMock });
    expect(second.fromCache).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("revalidates with If-None-Match when TTL expired and accepts 304", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(manifest), { status: 200, headers: { etag: '"v1"' } })
      )
      .mockResolvedValueOnce(new Response(null, { status: 304 }));

    const url = "https://t.example/.well-known/tsp/keys.json";
    await fetchManifest(url, { fetch: fetchMock, ttlMs: 0 });
    const second = await fetchManifest(url, { fetch: fetchMock, ttlMs: 0 });
    expect(second.manifest.sequence).toBe(1);
    expect(second.revalidated).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const secondCallHeaders = (fetchMock.mock.calls[1][1] as RequestInit).headers as Record<string, string>;
    expect(secondCallHeaders["If-None-Match"]).toBe('"v1"');
  });

  it("throws on non-2xx, non-304 response", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 404 }));
    await expect(
      fetchManifest("https://t.example/.well-known/tsp/keys.json", { fetch: fetchMock })
    ).rejects.toThrow(/404/);
  });
});
