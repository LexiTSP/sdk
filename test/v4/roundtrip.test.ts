/**
 * v4 round-trip tests — EXPERIMENTAL (RFC 0001 reference).
 *
 * Proves the substrate property: the same wrap()/verifyLocal() pair
 * round-trips correctly across all four registered provenance kinds.
 * Anything that round-trips for one kind round-trips for all of them
 * because the signing and verification math is unchanged across kinds —
 * which is exactly what substrate means.
 */

import { describe, it, expect } from "vitest";
import { wrap } from "../../src/v4/envelope";
import { verifyLocal, verifyAny } from "../../src/v4/verify";
import {
  generateKeyPair,
  exportPublicKeyJwk,
  sign,
} from "../../src/v4/index";
import { TSP_V4_VERSION } from "../../src/v4/types";
import {
  aiProfile,
  credentialProfile,
  attestationProfile,
  supplyChainProfile,
} from "../../src/v4/index";
import {
  sampleAiProvenance,
  sampleAttestationProvenance,
  sampleCredentialProvenance,
  sampleDeclaration,
  sampleQA,
  sampleSupplyChainProvenance,
} from "./fixtures";

async function makeSigner() {
  const kp = await generateKeyPair();
  const jwk = await exportPublicKeyJwk(kp.publicKey);
  const signer = {
    sign: (data: Uint8Array) => sign(kp.privateKey, data),
    publicKey: jwk,
    keyRef: "https://example.test/.well-known/tsp/keys.json#k1",
    certChain: [] as string[],
  };
  return { signer, jwk };
}

describe("v4 wrap → verifyLocal round-trip", () => {
  it("kind: ai — same shape v3 carried, just renamed", async () => {
    const { signer, jwk } = await makeSigner();
    const env = await wrap(
      { type: "text", value: "Hello, world." },
      {
        signer,
        declaration: sampleDeclaration,
        provenance: sampleAiProvenance,
        qa: sampleQA,
        prevHash: "0".repeat(64),
        skipTsa: true,
      },
    );
    expect(env.tsp).toBe(TSP_V4_VERSION);
    expect(env.provenance.kind).toBe("ai");
    const result = await verifyLocal(env, { knownPublicKey: jwk });
    expect(result.valid).toBe(true);
  });

  it("kind: credential — web-course example", async () => {
    const { signer, jwk } = await makeSigner();
    const env = await wrap(
      { type: "document", value: "Bachelor of Science, Computer Science" },
      {
        signer,
        declaration: sampleDeclaration,
        provenance: sampleCredentialProvenance,
        qa: sampleQA,
        prevHash: "0".repeat(64),
        skipTsa: true,
      },
    );
    expect(env.tsp).toBe(TSP_V4_VERSION);
    expect(env.provenance.kind).toBe("credential");
    const result = await verifyLocal(env, { knownPublicKey: jwk });
    expect(result.valid).toBe(true);
  });

  it("kind: attestation — general 'X happened' claim", async () => {
    const { signer, jwk } = await makeSigner();
    const env = await wrap(
      { type: "structured", value: '{"event":"deploy","tag":"v0.1.0-alpha.1"}' },
      {
        signer,
        declaration: sampleDeclaration,
        provenance: sampleAttestationProvenance,
        qa: sampleQA,
        prevHash: "0".repeat(64),
        skipTsa: true,
      },
    );
    expect(env.tsp).toBe(TSP_V4_VERSION);
    expect(env.provenance.kind).toBe("attestation");
    const result = await verifyLocal(env, { knownPublicKey: jwk });
    expect(result.valid).toBe(true);
  });

  it("kind: supply-chain — origin + transformations", async () => {
    const { signer, jwk } = await makeSigner();
    const env = await wrap(
      { type: "document", value: "Batch manifest #42" },
      {
        signer,
        declaration: sampleDeclaration,
        provenance: sampleSupplyChainProvenance,
        qa: sampleQA,
        prevHash: "0".repeat(64),
        skipTsa: true,
      },
    );
    expect(env.tsp).toBe(TSP_V4_VERSION);
    expect(env.provenance.kind).toBe("supply-chain");
    const result = await verifyLocal(env, { knownPublicKey: jwk });
    expect(result.valid).toBe(true);
  });
});

describe("v4 profile helpers produce correctly-shaped Provenance", () => {
  it("aiProfile", () => {
    const p = aiProfile({
      model: sampleAiProvenance.model,
      systemPrompt: sampleAiProvenance.systemPrompt,
    });
    expect(p.kind).toBe("ai");
  });

  it("credentialProfile", () => {
    const p = credentialProfile({
      issuer: sampleCredentialProvenance.issuer,
      criteria: sampleCredentialProvenance.criteria,
      achievedAt: sampleCredentialProvenance.achievedAt,
    });
    expect(p.kind).toBe("credential");
  });

  it("attestationProfile", () => {
    const p = attestationProfile({
      attester: sampleAttestationProvenance.attester,
      claim: sampleAttestationProvenance.claim,
      basis: sampleAttestationProvenance.basis,
    });
    expect(p.kind).toBe("attestation");
  });

  it("supplyChainProfile", () => {
    const p = supplyChainProfile({
      origin: sampleSupplyChainProvenance.origin,
      transformations: sampleSupplyChainProvenance.transformations,
    });
    expect(p.kind).toBe("supply-chain");
  });
});

describe("v4 enforces the kind registry at wrap time", () => {
  it("refuses to wrap an unregistered kind", async () => {
    const { signer } = await makeSigner();
    await expect(
      wrap(
        { type: "text", value: "hello" },
        {
          signer,
          declaration: sampleDeclaration,
          // Cast through unknown to bypass TS — the runtime check is the point.
          provenance: { kind: "vote", ballot: "yes" } as unknown as
            (typeof sampleAiProvenance),
          qa: sampleQA,
          prevHash: "0".repeat(64),
          skipTsa: true,
        },
      ),
    ).rejects.toThrow(/unknown provenance\.kind/);
  });
});

describe("v4 detects tampering", () => {
  it("rejects content mutation after signing", async () => {
    const { signer, jwk } = await makeSigner();
    const env = await wrap(
      { type: "text", value: "original" },
      {
        signer,
        declaration: sampleDeclaration,
        provenance: sampleCredentialProvenance,
        qa: sampleQA,
        prevHash: "0".repeat(64),
        skipTsa: true,
      },
    );
    const tampered = JSON.parse(JSON.stringify(env)) as typeof env;
    tampered.content.value = "tampered";
    const result = await verifyLocal(tampered, { knownPublicKey: jwk });
    expect(result.valid).toBe(false);
    expect(result.checks.contentHash.status).toBe("failed");
  });

  it("rejects provenance mutation after signing", async () => {
    const { signer, jwk } = await makeSigner();
    const env = await wrap(
      { type: "document", value: "diploma" },
      {
        signer,
        declaration: sampleDeclaration,
        provenance: sampleCredentialProvenance,
        qa: sampleQA,
        prevHash: "0".repeat(64),
        skipTsa: true,
      },
    );
    const tampered = JSON.parse(JSON.stringify(env)) as typeof env;
    if (tampered.provenance.kind === "credential") {
      tampered.provenance.issuer.name = "Different University";
    }
    const result = await verifyLocal(tampered, { knownPublicKey: jwk });
    expect(result.valid).toBe(false);
    // Both the ledger hash and the signature will fail; either is enough.
    const signaturesFailed = result.checks.signatures.some(
      (s) => s.status === "failed",
    );
    expect(
      result.checks.ledgerHash.status === "failed" || signaturesFailed,
    ).toBe(true);
  });
});
