import { describe, it, expect } from "vitest";
import {
  parseTLV,
  children,
  parseInteger,
  parseOID,
  parseGeneralizedTime,
  parseOctetString,
  TagClass,
  UTag,
} from "../../src/v3/asn1";

// Helper: hex string to Uint8Array for readable test fixtures
function h(s: string): Uint8Array {
  const clean = s.replace(/\s+/g, "");
  if (clean.length % 2) throw new Error("hex string must be even");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

describe("ASN.1 parseTLV", () => {
  it("parses a short-form INTEGER tag/length/value", () => {
    // 02 01 05 = INTEGER 5
    const buf = h("02 01 05");
    const tlv = parseTLV(buf);
    expect(tlv.tagClass).toBe(TagClass.UNIVERSAL);
    expect(tlv.constructed).toBe(false);
    expect(tlv.tag).toBe(UTag.INTEGER);
    expect(tlv.length).toBe(1);
    expect(tlv.totalLength).toBe(3);
  });

  it("parses long-form length", () => {
    // 04 81 80 followed by 128 bytes — OCTET STRING of length 128
    const len = 128;
    const fill = new Uint8Array(len).fill(0xab);
    const buf = new Uint8Array(3 + len);
    buf[0] = 0x04;
    buf[1] = 0x81;
    buf[2] = 0x80;
    buf.set(fill, 3);
    const tlv = parseTLV(buf);
    expect(tlv.length).toBe(128);
    expect(tlv.totalLength).toBe(131);
  });

  it("rejects indefinite length", () => {
    const buf = h("30 80 00 00");
    expect(() => parseTLV(buf)).toThrow(/indefinite/);
  });
});

describe("ASN.1 parseInteger", () => {
  it("decodes positive integers", () => {
    expect(parseInteger(h("02 01 05"), parseTLV(h("02 01 05")))).toBe(5n);
    expect(parseInteger(h("02 02 01 00"), parseTLV(h("02 02 01 00")))).toBe(256n);
  });

  it("decodes negative integers via two's complement", () => {
    // 02 01 FF = -1
    expect(parseInteger(h("02 01 FF"), parseTLV(h("02 01 FF")))).toBe(-1n);
  });

  it("decodes zero from empty value", () => {
    expect(parseInteger(h("02 00"), parseTLV(h("02 00")))).toBe(0n);
  });
});

describe("ASN.1 parseOID", () => {
  it("decodes a known OID (sha256, 2.16.840.1.101.3.4.2.1)", () => {
    // 06 09 60 86 48 01 65 03 04 02 01
    const buf = h("06 09 60 86 48 01 65 03 04 02 01");
    expect(parseOID(buf, parseTLV(buf))).toBe("2.16.840.1.101.3.4.2.1");
  });

  it("decodes id-signedData (1.2.840.113549.1.7.2)", () => {
    const buf = h("06 09 2A 86 48 86 F7 0D 01 07 02");
    expect(parseOID(buf, parseTLV(buf))).toBe("1.2.840.113549.1.7.2");
  });
});

describe("ASN.1 parseGeneralizedTime", () => {
  it("decodes YYYYMMDDHHMMSSZ", () => {
    // GeneralizedTime "20260430120000Z" — DER bytes
    const dateStr = "20260430120000Z";
    const dateBytes = new TextEncoder().encode(dateStr);
    const buf = new Uint8Array(2 + dateBytes.length);
    buf[0] = 0x18;
    buf[1] = dateBytes.length;
    buf.set(dateBytes, 2);
    const tlv = parseTLV(buf);
    const d = parseGeneralizedTime(buf, tlv);
    expect(d.toISOString()).toBe("2026-04-30T12:00:00.000Z");
  });
});

describe("ASN.1 children + nesting", () => {
  it("walks a SEQUENCE of two INTEGERs", () => {
    // 30 06 02 01 05 02 01 0A
    const buf = h("30 06 02 01 05 02 01 0A");
    const root = parseTLV(buf);
    expect(root.constructed).toBe(true);
    const kids = children(buf, root);
    expect(kids).toHaveLength(2);
    expect(parseInteger(buf, kids[0])).toBe(5n);
    expect(parseInteger(buf, kids[1])).toBe(10n);
  });
});

describe("ASN.1 parseOctetString", () => {
  it("returns the value bytes of OCTET STRING", () => {
    const buf = h("04 03 DE AD BE");
    const tlv = parseTLV(buf);
    const v = parseOctetString(buf, tlv);
    expect(Array.from(v)).toEqual([0xde, 0xad, 0xbe]);
  });
});
