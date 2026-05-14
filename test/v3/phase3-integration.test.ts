import { describe, it, expect, beforeEach, vi } from "vitest";
import { wrap, TSA_PLACEHOLDER_TOKEN } from "../../src/v3/envelope";
import { verifyOnline } from "../../src/v3/verify-online";
import { generateKeyPair, exportPublicKeyJwk, sign as sigSign } from "../../src/v3/crypto";
import { signInstanceCert, signManifest, type RootSigner } from "../../src/v3/manifest-sign";
import { clearManifestCache } from "../../src/v3/manifest-fetch";
import { clearSequenceState } from "../../src/v3/sequence-state";
import { canonicalize } from "../../src/v3/canonical";
import { sha256Hex } from "../../src/v3/canonical-hash";
import { sampleDeclaration, sampleProcess, sampleAlignment } from "./fixtures";

const URL = "https://test.example/.well-known/tsp/keys.json";

async function setupOrgAndEnv() {
  const rootKp = await generateKeyPair();
  const rootJwk = await exportPublicKeyJwk(rootKp.publicKey);
  const root: RootSigner = {
    sign: (data) => sigSign(rootKp.privateKey, data),
    publicKey: rootJwk,
  };
  const instKp = await generateKeyPair();
  const instJwk = await exportPublicKeyJwk(instKp.publicKey);
  const cert = await signInstanceCert({
    rootSigner: root,
    payload: {
      id: "i1",
      publicKey: instJwk,
      validFrom: "2020-01-01T00:00:00Z",
      validUntil: "2099-01-01T00:00:00Z",
    },
  });
  const manifest = await signManifest({
    rootSigner: root,
    organization: { name: "Test", domain: "test.example" },
    instances: [cert],
    revoked: [],
    sequence: 1,
    issuedAt: new Date().toISOString(),
    acceptableAge: { seconds: 86400 * 365 },
  });
  const signer = {
    sign: (data: Uint8Array) => sigSign(instKp.privateKey, data),
    publicKey: instJwk,
    keyRef: `${URL}#i1`,
    certChain: [],
  };
  const env = await wrap(
    { type: "text", value: "phase3" },
    {
      signer,
      declaration: sampleDeclaration,
      process: sampleProcess,
      alignment: sampleAlignment,
      prevHash: "0".repeat(64),
    }
  );
  return { manifest, env };
}

function mockManifestFetch(manifest: unknown) {
  return vi.fn().mockResolvedValue(
    new Response(JSON.stringify(manifest), { status: 200, headers: { etag: '"v1"' } })
  );
}

beforeEach(() => {
  clearManifestCache();
  clearSequenceState();
});

describe("Phase 3 — placeholder TSA token handling", () => {
  it("envelope wrapped without TSA carries placeholder token", async () => {
    const { env } = await setupOrgAndEnv();
    expect(env.timestamp.tsaToken).toBe(TSA_PLACEHOLDER_TOKEN);
  });

  it("verifyOnline rejects placeholder without acceptLegacyTsa", async () => {
    const { manifest, env } = await setupOrgAndEnv();
    const r = await verifyOnline(env, { fetch: mockManifestFetch(manifest) });
    expect(r.valid).toBe(false);
    expect(r.checks.tsa.status).toBe("failed");
    expect(r.checks.tsa.detail).toMatch(/placeholder/i);
  });

  it("verifyOnline accepts placeholder with acceptLegacyTsa: true", async () => {
    const { manifest, env } = await setupOrgAndEnv();
    const r = await verifyOnline(env, {
      fetch: mockManifestFetch(manifest),
      acceptLegacyTsa: true,
    });
    expect(r.valid).toBe(true);
    expect(r.checks.tsa.status).toBe("skipped");
    expect(r.warnings).toContain(
      "envelope has legacy placeholder tsaToken; no real TSA attestation"
    );
  });
});

describe("Phase 3 — DANE integration with verifyOnline", () => {
  it("requireDane=true with valid DANE response → valid", async () => {
    const { manifest, env } = await setupOrgAndEnv();
    const expectedRootHash = await sha256Hex(canonicalize(manifest.rootKey));

    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes(".well-known/tsp/keys.json")) {
        return new Response(JSON.stringify(manifest), { status: 200, headers: { etag: '"v1"' } });
      }
      if (url.includes("dns-query")) {
        return new Response(
          JSON.stringify({
            Status: 0,
            AD: true,
            Answer: [
              {
                name: "_tsp.test.example",
                type: 16,
                data: `"v=tsp1; rootKeyHash=sha256-${expectedRootHash}"`,
              },
            ],
          }),
          { status: 200 }
        );
      }
      return new Response(null, { status: 404 });
    });

    const r = await verifyOnline(env, {
      fetch: fetchMock,
      acceptLegacyTsa: true,
      requireDane: true,
      daneOptions: { fetch: fetchMock },
    });
    expect(r.valid).toBe(true);
    expect(r.checks.dane?.status).toBe("passed");
  });

  it("requireDane=true with AD=false → invalid", async () => {
    const { manifest, env } = await setupOrgAndEnv();
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes(".well-known/tsp/keys.json")) {
        return new Response(JSON.stringify(manifest), { status: 200, headers: { etag: '"v1"' } });
      }
      if (url.includes("dns-query")) {
        return new Response(
          JSON.stringify({ Status: 0, AD: false, Answer: [] }),
          { status: 200 }
        );
      }
      return new Response(null, { status: 404 });
    });
    const r = await verifyOnline(env, {
      fetch: fetchMock,
      acceptLegacyTsa: true,
      requireDane: true,
      daneOptions: { fetch: fetchMock },
    });
    expect(r.valid).toBe(false);
    expect(r.checks.dane?.status).toBe("failed");
  });
});
