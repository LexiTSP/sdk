import { describe, it, expect } from "vitest";
import {
  signInstanceCert,
  signManifest,
  type InstanceCertSignInput,
  type ManifestSignInput,
} from "../../src/v3/manifest-sign";
import { generateKeyPair, exportPublicKeyJwk, sign as sigSign, importPublicKeyJwk, verify as sigVerify } from "../../src/v3/crypto";
import { canonicalize } from "../../src/v3/canonical";

const enc = new TextEncoder();

async function makeRootSigner() {
  const kp = await generateKeyPair();
  const jwk = await exportPublicKeyJwk(kp.publicKey);
  return {
    sign: (data: Uint8Array) => sigSign(kp.privateKey, data),
    publicKey: jwk,
  };
}

describe("signInstanceCert()", () => {
  it("produces a base64 signature over canonical payload", async () => {
    const root = await makeRootSigner();
    const instanceKp = await generateKeyPair();
    const instanceJwk = await exportPublicKeyJwk(instanceKp.publicKey);

    const input: InstanceCertSignInput = {
      rootSigner: root,
      payload: {
        id: "instance-2026-Q2-1",
        publicKey: instanceJwk,
        validFrom: "2026-04-01T00:00:00Z",
        validUntil: "2026-04-30T23:59:59Z",
      },
    };

    const cert = await signInstanceCert(input);

    expect(cert.id).toBe(input.payload.id);
    expect(cert.publicKey).toEqual(instanceJwk);
    expect(typeof cert.rootSignature).toBe("string");
    expect(cert.rootSignature.length).toBeGreaterThan(0);

    const rootPub = await importPublicKeyJwk(root.publicKey);
    const sigBytes = Uint8Array.from(atob(cert.rootSignature), (c) => c.charCodeAt(0));
    const ok = await sigVerify(rootPub, sigBytes, enc.encode(canonicalize(input.payload)));
    expect(ok).toBe(true);
  });
});

describe("signManifest()", () => {
  it("produces a manifest with valid rootSignatureOverManifest", async () => {
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

    const input: ManifestSignInput = {
      rootSigner: root,
      organization: { name: "TestOrg", domain: "test.example" },
      instances: [cert],
      revoked: [],
      sequence: 1,
      issuedAt: "2026-04-30T12:00:00Z",
      acceptableAge: { seconds: 86400 },
    };

    const manifest = await signManifest(input);

    expect(manifest.tsp).toBe("3.0");
    expect(manifest.organization.domain).toBe("test.example");
    expect(manifest.sequence).toBe(1);
    expect(typeof manifest.rootSignatureOverManifest).toBe("string");

    const { rootSignatureOverManifest, ...unsigned } = manifest;
    const rootPub = await importPublicKeyJwk(root.publicKey);
    const sigBytes = Uint8Array.from(atob(rootSignatureOverManifest), (c) => c.charCodeAt(0));
    const ok = await sigVerify(rootPub, sigBytes, enc.encode(canonicalize(unsigned)));
    expect(ok).toBe(true);
  });
});
