import { describe, it, expect } from "vitest";
import { wrap } from "../../src/v3/envelope";
import { generateKeyPair, exportPublicKeyJwk, sign } from "../../src/v3/crypto";
import { sampleDeclaration, sampleProcess, sampleAlignment } from "./fixtures";
import type { Signer } from "../../src/v3/envelope";

async function makeSigner(): Promise<Signer> {
  const kp = await generateKeyPair();
  const jwk = await exportPublicKeyJwk(kp.publicKey);
  return {
    sign: (data) => sign(kp.privateKey, data),
    publicKey: jwk,
    keyRef: "https://example.test/.well-known/tsp/keys.json#instance-test",
    certChain: [],
  };
}

describe("wrap()", () => {
  it("produces an envelope with tsp version 3.0", async () => {
    const signer = await makeSigner();
    const env = await wrap(
      { type: "text", value: "Hello" },
      {
        signer,
        declaration: sampleDeclaration,
        process: sampleProcess,
        alignment: sampleAlignment,
        prevHash: "0".repeat(64),
      }
    );
    expect(env.tsp).toBe("3.0");
  });

  it("populates content.hash as sha256 of canonical(value)", async () => {
    const signer = await makeSigner();
    const env = await wrap(
      { type: "text", value: "Hello" },
      {
        signer,
        declaration: sampleDeclaration,
        process: sampleProcess,
        alignment: sampleAlignment,
        prevHash: "0".repeat(64),
      }
    );
    expect(env.content.hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it("ledger.id is a UUIDv7", async () => {
    const signer = await makeSigner();
    const env = await wrap(
      { type: "text", value: "x" },
      {
        signer,
        declaration: sampleDeclaration,
        process: sampleProcess,
        alignment: sampleAlignment,
        prevHash: "0".repeat(64),
      }
    );
    expect(env.ledger.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
    );
  });

  it("includes one signature with role=instance", async () => {
    const signer = await makeSigner();
    const env = await wrap(
      { type: "text", value: "x" },
      {
        signer,
        declaration: sampleDeclaration,
        process: sampleProcess,
        alignment: sampleAlignment,
        prevHash: "0".repeat(64),
      }
    );
    expect(env.signatures).toHaveLength(1);
    expect(env.signatures[0].role).toBe("instance");
    expect(env.signatures[0].algorithm).toBe("ed25519");
    expect(env.signatures[0].keyRef).toBe(signer.keyRef);
    expect(typeof env.signatures[0].signature).toBe("string");
  });

  it("ledger.hash matches sha256(canonical(envelope − ledger.hash))", async () => {
    const signer = await makeSigner();
    const env = await wrap(
      { type: "text", value: "x" },
      {
        signer,
        declaration: sampleDeclaration,
        process: sampleProcess,
        alignment: sampleAlignment,
        prevHash: "0".repeat(64),
      }
    );
    const { canonicalize } = await import("../../src/v3/canonical");
    const { sha256Hex } = await import("../../src/v3/canonical-hash");
    const clone = JSON.parse(JSON.stringify(env));
    delete clone.ledger.hash;
    const expected = await sha256Hex(canonicalize(clone));
    expect(env.ledger.hash).toBe(expected);
  });
});
