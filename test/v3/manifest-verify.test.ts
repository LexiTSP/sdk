import { describe, it, expect } from "vitest";
import { verifyManifestSignature, verifyInstanceCert } from "../../src/v3/manifest-verify";
import { signInstanceCert, signManifest, type RootSigner } from "../../src/v3/manifest-sign";
import { generateKeyPair, exportPublicKeyJwk, sign as sigSign } from "../../src/v3/crypto";

async function makeRootSigner(): Promise<RootSigner> {
  const kp = await generateKeyPair();
  const jwk = await exportPublicKeyJwk(kp.publicKey);
  return {
    sign: (data) => sigSign(kp.privateKey, data),
    publicKey: jwk,
  };
}

async function makeFreshManifest() {
  const root = await makeRootSigner();
  const instanceKp = await generateKeyPair();
  const instanceJwk = await exportPublicKeyJwk(instanceKp.publicKey);

  const cert = await signInstanceCert({
    rootSigner: root,
    payload: {
      id: "instance-1",
      publicKey: instanceJwk,
      validFrom: "2026-04-01T00:00:00Z",
      validUntil: "2026-05-01T00:00:00Z",
    },
  });

  const manifest = await signManifest({
    rootSigner: root,
    organization: { name: "Test", domain: "test.example" },
    instances: [cert],
    revoked: [],
    sequence: 1,
    issuedAt: "2026-04-30T12:00:00Z",
    acceptableAge: { seconds: 86400 },
  });

  return { manifest, cert };
}

describe("verifyManifestSignature()", () => {
  it("returns true for an unmodified manifest", async () => {
    const { manifest } = await makeFreshManifest();
    expect(await verifyManifestSignature(manifest)).toBe(true);
  });

  it("returns false when manifest body is tampered", async () => {
    const { manifest } = await makeFreshManifest();
    const tampered = { ...manifest, sequence: 999 };
    expect(await verifyManifestSignature(tampered)).toBe(false);
  });

  it("returns false when rootSignatureOverManifest is corrupted", async () => {
    const { manifest } = await makeFreshManifest();
    const garbage = btoa(String.fromCharCode(...new Array(64).fill(0)));
    const tampered = { ...manifest, rootSignatureOverManifest: garbage };
    expect(await verifyManifestSignature(tampered)).toBe(false);
  });
});

describe("verifyInstanceCert()", () => {
  it("returns true for an unmodified instance cert", async () => {
    const { manifest, cert } = await makeFreshManifest();
    expect(await verifyInstanceCert(cert, manifest.rootKey)).toBe(true);
  });

  it("returns false when cert payload is tampered", async () => {
    const { manifest, cert } = await makeFreshManifest();
    const tampered = { ...cert, validUntil: "2030-01-01T00:00:00Z" };
    expect(await verifyInstanceCert(tampered, manifest.rootKey)).toBe(false);
  });
});
