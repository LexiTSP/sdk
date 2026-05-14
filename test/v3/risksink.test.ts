import { describe, it, expect, vi } from "vitest";
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

describe("wrap() riskSink option", () => {
  it("POSTs envelope JSON to riskSink.url with bearer auth", async () => {
    const signer = await makeSigner();
    const fakeFetch = vi.fn(async () => new Response(null, { status: 202 }));
    const env = await wrap(
      { type: "text", value: "Hello" },
      {
        signer,
        declaration: sampleDeclaration,
        process: sampleProcess,
        alignment: sampleAlignment,
        prevHash: "0".repeat(64),
        riskSink: {
          url: "https://risk.test/ingest",
          apiKey: "test-key-123",
          fetch: fakeFetch as unknown as typeof fetch,
        },
      }
    );
    // Allow void Promise to settle
    await new Promise((r) => setTimeout(r, 10));

    expect(fakeFetch).toHaveBeenCalledTimes(1);
    const [url, init] = fakeFetch.mock.calls[0]!;
    expect(url).toBe("https://risk.test/ingest");
    expect((init as RequestInit)?.method).toBe("POST");
    const headers = (init as RequestInit)?.headers as Record<string, string>;
    expect(headers["authorization"]).toBe("Bearer test-key-123");
    const body = JSON.parse((init as RequestInit)?.body as string);
    expect(body.tsp).toBe("3.0");
    expect(body.ledger.id).toBe(env.ledger.id);
  });

  it("does not block wrap() return on riskSink failure (warn mode)", async () => {
    const signer = await makeSigner();
    const failFetch = vi.fn(async () => {
      throw new Error("network down");
    });
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    const env = await wrap(
      { type: "text", value: "Hello" },
      {
        signer,
        declaration: sampleDeclaration,
        process: sampleProcess,
        alignment: sampleAlignment,
        prevHash: "0".repeat(64),
        riskSink: {
          url: "https://risk.test/ingest",
          apiKey: "k",
          onError: "warn",
          fetch: failFetch as unknown as typeof fetch,
        },
      }
    );
    expect(env.tsp).toBe("3.0");

    await new Promise((r) => setTimeout(r, 10));
    expect(warnSpy.mock.calls.some((c) => String(c[0]).includes("riskSink"))).toBe(true);
    warnSpy.mockRestore();
  });

  it("ignore mode swallows errors silently", async () => {
    const signer = await makeSigner();
    const failFetch = vi.fn(async () => {
      throw new Error("network down");
    });
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    await wrap(
      { type: "text", value: "Hello" },
      {
        signer,
        declaration: sampleDeclaration,
        process: sampleProcess,
        alignment: sampleAlignment,
        prevHash: "0".repeat(64),
        riskSink: {
          url: "https://risk.test/ingest",
          apiKey: "k",
          onError: "ignore",
          fetch: failFetch as unknown as typeof fetch,
        },
      }
    );

    await new Promise((r) => setTimeout(r, 10));
    const riskSinkWarns = warnSpy.mock.calls.filter((c) =>
      String(c[0]).includes("riskSink")
    );
    expect(riskSinkWarns.length).toBe(0);
    warnSpy.mockRestore();
  });

  it("treats non-2xx response as failure (warn mode)", async () => {
    const signer = await makeSigner();
    const fakeFetch = vi.fn(
      async () => new Response("denied", { status: 401, statusText: "Unauthorized" })
    );
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    await wrap(
      { type: "text", value: "Hello" },
      {
        signer,
        declaration: sampleDeclaration,
        process: sampleProcess,
        alignment: sampleAlignment,
        prevHash: "0".repeat(64),
        riskSink: {
          url: "https://risk.test/ingest",
          apiKey: "k",
          fetch: fakeFetch as unknown as typeof fetch,
        },
      }
    );

    await new Promise((r) => setTimeout(r, 10));
    expect(
      warnSpy.mock.calls.some((c) => String(c[0]).includes("401"))
    ).toBe(true);
    warnSpy.mockRestore();
  });
});
