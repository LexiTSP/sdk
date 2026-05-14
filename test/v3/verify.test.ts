import { describe, it, expect } from "vitest";
import { wrap } from "../../src/v3/envelope";
import { verifyLocal } from "../../src/v3/verify";
import { generateKeyPair, exportPublicKeyJwk, sign } from "../../src/v3/crypto";
import { sampleDeclaration, sampleProcess, sampleAlignment } from "./fixtures";
import type { Signer } from "../../src/v3/envelope";

async function makeSignerAndKey() {
  const kp = await generateKeyPair();
  const jwk = await exportPublicKeyJwk(kp.publicKey);
  const signer: Signer = {
    sign: (data) => sign(kp.privateKey, data),
    publicKey: jwk,
    keyRef: "https://example.test/.well-known/tsp/keys.json#instance-1",
    certChain: [],
  };
  return { signer, publicKeyJwk: jwk };
}

async function wrapDefault(signer: Signer) {
  return wrap(
    { type: "text", value: "Hello" },
    {
      signer,
      declaration: sampleDeclaration,
      process: sampleProcess,
      alignment: sampleAlignment,
      prevHash: "0".repeat(64),
    }
  );
}

describe("verifyLocal()", () => {
  it("returns valid:true for a freshly wrapped envelope", async () => {
    const { signer, publicKeyJwk } = await makeSignerAndKey();
    const env = await wrapDefault(signer);
    const result = await verifyLocal(env, { knownPublicKey: publicKeyJwk });
    expect(result.valid).toBe(true);
    expect(result.checks.contentHash.status).toBe("passed");
    expect(result.checks.ledgerHash.status).toBe("passed");
    expect(result.checks.signatures[0].status).toBe("passed");
  });

  it("flags content tampering via contentHash check", async () => {
    const { signer, publicKeyJwk } = await makeSignerAndKey();
    const env = await wrapDefault(signer);
    const tampered = { ...env, content: { ...env.content, value: "Goodbye" } };
    const result = await verifyLocal(tampered, { knownPublicKey: publicKeyJwk });
    expect(result.valid).toBe(false);
    expect(result.checks.contentHash.status).toBe("failed");
  });

  it("flags ledger tampering via ledgerHash check", async () => {
    const { signer, publicKeyJwk } = await makeSignerAndKey();
    const env = await wrapDefault(signer);
    const tampered = {
      ...env,
      ledger: { ...env.ledger, prevHash: "f".repeat(64) },
    };
    const result = await verifyLocal(tampered, { knownPublicKey: publicKeyJwk });
    expect(result.valid).toBe(false);
    expect(result.checks.ledgerHash.status).toBe("failed");
  });

  it("flags signature tampering via signatures check", async () => {
    const { signer, publicKeyJwk } = await makeSignerAndKey();
    const env = await wrapDefault(signer);
    const garbage = btoa(String.fromCharCode(...new Array(64).fill(0)));
    const tampered = {
      ...env,
      signatures: [{ ...env.signatures[0], signature: garbage }],
    };
    const result = await verifyLocal(tampered, { knownPublicKey: publicKeyJwk });
    expect(result.valid).toBe(false);
    expect(result.checks.signatures[0].status).toBe("failed");
  });

  it("manifest/TSA/cert-chain checks are skipped in local mode", async () => {
    const { signer, publicKeyJwk } = await makeSignerAndKey();
    const env = await wrapDefault(signer);
    const result = await verifyLocal(env, { knownPublicKey: publicKeyJwk });
    expect(result.checks.manifestFetch.status).toBe("skipped");
    expect(result.checks.tsa.status).toBe("skipped");
    expect(result.checks.certChain.status).toBe("skipped");
    expect(result.checks.rootSignature.status).toBe("skipped");
    expect(result.checks.certValidity.status).toBe("skipped");
    expect(result.checks.revocation.status).toBe("skipped");
  });

  it("schema check fails when tsp version is wrong", async () => {
    const { signer, publicKeyJwk } = await makeSignerAndKey();
    const env = await wrapDefault(signer);
    const wrongVersion = { ...env, tsp: "2.0" as never };
    const result = await verifyLocal(wrongVersion, {
      knownPublicKey: publicKeyJwk,
    });
    expect(result.valid).toBe(false);
    expect(result.checks.schema.status).toBe("failed");
  });
});
