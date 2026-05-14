import { describe, it, expect } from "vitest";
import { wrap } from "../../src/v3/envelope";
import { verifyLocal } from "../../src/v3/verify";
import { generateKeyPair, exportPublicKeyJwk, sign } from "../../src/v3/crypto";
import { sampleDeclaration, sampleProcess, sampleAlignment } from "./fixtures";
import fc from "fast-check";

describe("v3 wrap → verifyLocal round-trip", () => {
  it("any well-formed wrap produces an envelope verifyLocal accepts", async () => {
    const kp = await generateKeyPair();
    const jwk = await exportPublicKeyJwk(kp.publicKey);
    const signer = {
      sign: (data: Uint8Array) => sign(kp.privateKey, data),
      publicKey: jwk,
      keyRef: "https://example.test/.well-known/tsp/keys.json#k1",
      certChain: [] as string[],
    };

    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 1024 }),
        async (value) => {
          const env = await wrap(
            { type: "text", value },
            {
              signer,
              declaration: sampleDeclaration,
              process: sampleProcess,
              alignment: sampleAlignment,
              prevHash: "0".repeat(64),
            }
          );
          const result = await verifyLocal(env, { knownPublicKey: jwk });
          return result.valid;
        }
      ),
      { numRuns: 30 }
    );
  });
});
