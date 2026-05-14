import { describe, it, expect, beforeEach, vi } from "vitest";
import { wrap } from "../../src/v3/envelope";
import { verifyOnline } from "../../src/v3/verify-online";
import { generateKeyPair, exportPublicKeyJwk, sign as sigSign } from "../../src/v3/crypto";
import { signInstanceCert, signManifest, type RootSigner } from "../../src/v3/manifest-sign";
import { clearManifestCache } from "../../src/v3/manifest-fetch";
import { clearSequenceState, recordSequence } from "../../src/v3/sequence-state";
import { sampleDeclaration, sampleProcess, sampleAlignment } from "./fixtures";

const URL = "https://test.example/.well-known/tsp/keys.json";

async function setupOrg(opts: { instanceId: string; validity?: { from: string; until: string } }) {
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
      id: opts.instanceId,
      publicKey: instJwk,
      validFrom: opts.validity?.from ?? "2020-01-01T00:00:00Z",
      validUntil: opts.validity?.until ?? "2099-01-01T00:00:00Z",
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

  const instanceSigner = {
    sign: (data: Uint8Array) => sigSign(instKp.privateKey, data),
    publicKey: instJwk,
    keyRef: `${URL}#${opts.instanceId}`,
    certChain: [],
  };

  return { manifest, instanceSigner };
}

function mockFetch(manifestObj: unknown) {
  return vi.fn().mockResolvedValue(
    new Response(JSON.stringify(manifestObj), { status: 200, headers: { etag: '"v1"' } })
  );
}

beforeEach(() => {
  clearManifestCache();
  clearSequenceState();
});

describe("verifyOnline()", () => {
  it("returns valid:true for a freshly wrapped envelope with a fresh manifest", async () => {
    const { manifest, instanceSigner } = await setupOrg({ instanceId: "i1" });
    const env = await wrap(
      { type: "text", value: "hi" },
      {
        signer: instanceSigner,
        declaration: sampleDeclaration,
        process: sampleProcess,
        alignment: sampleAlignment,
        prevHash: "0".repeat(64),
      }
    );
    const r = await verifyOnline(env, { fetch: mockFetch(manifest), acceptLegacyTsa: true });
    expect(r.valid).toBe(true);
    expect(r.checks.manifestFetch.status).toBe("passed");
    expect(r.checks.rootSignature.status).toBe("passed");
    expect(r.checks.certChain.status).toBe("passed");
    expect(r.checks.certValidity.status).toBe("passed");
    expect(r.checks.revocation.status).toBe("passed");
  });

  it("returns valid:false on rollback", async () => {
    const { manifest, instanceSigner } = await setupOrg({ instanceId: "i1" });
    const env = await wrap(
      { type: "text", value: "hi" },
      {
        signer: instanceSigner,
        declaration: sampleDeclaration,
        process: sampleProcess,
        alignment: sampleAlignment,
        prevHash: "0".repeat(64),
      }
    );
    recordSequence("test.example", 99);
    const r = await verifyOnline(env, { fetch: mockFetch(manifest), acceptLegacyTsa: true });
    expect(r.valid).toBe(false);
    expect(r.checks.manifestFetch.status).toBe("failed");
    expect(r.checks.manifestFetch.detail).toMatch(/rollback/i);
  });

  it("returns valid:false when network fetch fails", async () => {
    const { instanceSigner } = await setupOrg({ instanceId: "i1" });
    const env = await wrap(
      { type: "text", value: "hi" },
      {
        signer: instanceSigner,
        declaration: sampleDeclaration,
        process: sampleProcess,
        alignment: sampleAlignment,
        prevHash: "0".repeat(64),
      }
    );
    const fetchMock = vi.fn().mockRejectedValue(new Error("ENETUNREACH"));
    const r = await verifyOnline(env, { fetch: fetchMock, acceptLegacyTsa: true });
    expect(r.valid).toBe(false);
    expect(r.checks.manifestFetch.status).toBe("failed");
  });

  it("returns valid:false when instance not in manifest", async () => {
    const { manifest } = await setupOrg({ instanceId: "i1" });
    const { instanceSigner } = await setupOrg({ instanceId: "i999" });
    const env = await wrap(
      { type: "text", value: "hi" },
      {
        signer: instanceSigner,
        declaration: sampleDeclaration,
        process: sampleProcess,
        alignment: sampleAlignment,
        prevHash: "0".repeat(64),
      }
    );
    const r = await verifyOnline(env, { fetch: mockFetch(manifest), acceptLegacyTsa: true });
    expect(r.valid).toBe(false);
    expect(r.checks.certChain.status).toBe("failed");
  });

  it("returns valid:false when envelope timestamp is outside cert validity", async () => {
    const { manifest, instanceSigner } = await setupOrg({
      instanceId: "i1",
      validity: { from: "2099-01-01T00:00:00Z", until: "2099-12-31T00:00:00Z" },
    });
    const env = await wrap(
      { type: "text", value: "hi" },
      {
        signer: instanceSigner,
        declaration: sampleDeclaration,
        process: sampleProcess,
        alignment: sampleAlignment,
        prevHash: "0".repeat(64),
      }
    );
    const r = await verifyOnline(env, { fetch: mockFetch(manifest), acceptLegacyTsa: true });
    expect(r.valid).toBe(false);
    expect(r.checks.certValidity.status).toBe("failed");
  });
});
