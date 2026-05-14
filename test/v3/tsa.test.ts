import { describe, it, expect, vi } from "vitest";
import { buildTimeStampReq, stampHash } from "../../src/v3/tsa";
import { parseTLV, children, parseInteger, parseOID, TagClass, UTag } from "../../src/v3/asn1";

describe("buildTimeStampReq", () => {
  it("produces a valid SEQUENCE with version=1, messageImprint, nonce", () => {
    const hash = new Uint8Array(32).fill(0xab);
    const nonce = 12345n;
    const req = buildTimeStampReq({ hash, nonce, certReq: true });

    const root = parseTLV(req);
    expect(root.tagClass).toBe(TagClass.UNIVERSAL);
    expect(root.tag).toBe(UTag.SEQUENCE);
    expect(root.constructed).toBe(true);

    const kids = children(req, root);
    // version
    expect(parseInteger(req, kids[0])).toBe(1n);
    // messageImprint (SEQUENCE)
    expect(kids[1].tag).toBe(UTag.SEQUENCE);
    const miKids = children(req, kids[1]);
    const algIdent = miKids[0];
    const oid = parseOID(req, children(req, algIdent)[0]);
    expect(oid).toBe("2.16.840.1.101.3.4.2.1"); // SHA-256
    // hashedMessage = OCTET STRING
    expect(miKids[1].tag).toBe(UTag.OCTET_STRING);
    expect(miKids[1].length).toBe(32);
    // nonce
    expect(parseInteger(req, kids[2])).toBe(12345n);
  });
});

describe("stampHash", () => {
  it("throws when no URLs configured", async () => {
    await expect(stampHash(new Uint8Array(32), { urls: [] })).rejects.toThrow(/no TSA URLs/);
  });

  it("returns aggregated error when all TSAs fail", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(new Response(null, { status: 500 }))
      .mockResolvedValueOnce(new Response(null, { status: 503 }));
    await expect(
      stampHash(new Uint8Array(32), {
        urls: ["https://tsa1.test/", "https://tsa2.test/"],
        fetch: fetchMock,
      })
    ).rejects.toThrow(/all TSAs failed/);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("falls back to next TSA on first failure", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 500 }));
    await expect(
      stampHash(new Uint8Array(32), {
        urls: ["https://a.test/", "https://b.test/", "https://c.test/"],
        fetch: fetchMock,
      })
    ).rejects.toThrow();
    // Should have tried all three
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});
