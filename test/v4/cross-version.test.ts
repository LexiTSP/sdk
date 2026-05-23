/**
 * Cross-version compatibility tests — EXPERIMENTAL.
 *
 * Proves the compatibility promise in RFC 0001:
 *   - v4 envelopes carry tsp: "4.0-draft" and verify under the v4 verifier.
 *   - v3 envelopes carry tsp: "3.0" and remain valid; verifyAny routes them
 *     to the v3 verifier.
 *   - Unknown versions return a structured "unknown" result rather than
 *     throwing.
 *
 * This is the structural guarantee that lets v3 issuers keep operating
 * after v4 ships without coordinating an upgrade.
 */

import { describe, it, expect } from "vitest";
import { wrap as wrapV3 } from "../../src/v3/envelope";
import {
  generateKeyPair as generateKeyPairV3,
  exportPublicKeyJwk as exportPublicKeyJwkV3,
  sign as signV3,
} from "../../src/v3/crypto";
import { wrap as wrapV4 } from "../../src/v4/envelope";
import { verifyAny } from "../../src/v4/verify";
import {
  sampleAlignment,
  sampleDeclaration as sampleDeclarationV3,
  sampleProcess,
} from "../v3/fixtures";
import {
  sampleCredentialProvenance,
  sampleDeclaration as sampleDeclarationV4,
  sampleQA,
} from "./fixtures";

describe("verifyAny dispatches by tsp wire version", () => {
  it("routes a v3 envelope to v3 verifier and accepts it", async () => {
    const kp = await generateKeyPairV3();
    const jwk = await exportPublicKeyJwkV3(kp.publicKey);
    const env = await wrapV3(
      { type: "text", value: "v3 envelope" },
      {
        signer: {
          sign: (data: Uint8Array) => signV3(kp.privateKey, data),
          publicKey: jwk,
          keyRef: "https://example.test/.well-known/tsp/keys.json#k1",
          certChain: [],
        },
        declaration: sampleDeclarationV3,
        process: sampleProcess,
        alignment: sampleAlignment,
        prevHash: "0".repeat(64),
      },
    );
    const out = await verifyAny(env, { knownPublicKey: jwk });
    expect(out.version).toBe("3.0");
    if (out.version === "3.0") {
      expect(out.result.valid).toBe(true);
    }
  });

  it("routes a v4-draft envelope to v4 verifier and accepts it", async () => {
    const kp = await generateKeyPairV3();
    const jwk = await exportPublicKeyJwkV3(kp.publicKey);
    const env = await wrapV4(
      { type: "document", value: "credential payload" },
      {
        signer: {
          sign: (data: Uint8Array) => signV3(kp.privateKey, data),
          publicKey: jwk,
          keyRef: "did:web:bi.no#issuer-key-1",
          certChain: [],
        },
        declaration: sampleDeclarationV4,
        provenance: sampleCredentialProvenance,
        qa: sampleQA,
        prevHash: "0".repeat(64),
        skipTsa: true,
      },
    );
    const out = await verifyAny(env, { knownPublicKey: jwk });
    expect(out.version).toBe("4.0-draft");
    if (out.version === "4.0-draft") {
      expect(out.result.valid).toBe(true);
    }
  });

  it("returns a structured 'unknown' for unsupported tsp values", async () => {
    const kp = await generateKeyPairV3();
    const jwk = await exportPublicKeyJwkV3(kp.publicKey);
    const out = await verifyAny(
      { tsp: "99.0", content: {}, ledger: {}, signatures: [] },
      { knownPublicKey: jwk },
    );
    expect(out.version).toBe("unknown");
    if (out.version === "unknown") {
      expect(out.reason).toMatch(/unsupported tsp version/);
    }
  });

  it("returns 'unknown' for non-objects", async () => {
    const kp = await generateKeyPairV3();
    const jwk = await exportPublicKeyJwkV3(kp.publicKey);
    const out = await verifyAny(null, { knownPublicKey: jwk });
    expect(out.version).toBe("unknown");
  });
});
