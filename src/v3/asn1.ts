/**
 * @lexitsp/sdk v3 · minimal ASN.1 BER/DER decoder
 *
 * Scope: just enough to extract MessageImprint, genTime, nonce, signature, and
 * embedded TSA cert from an RFC 3161 TimeStampToken (CMS SignedData).
 *
 * No INDEFINITE-LENGTH support (DER doesn't use it). No streaming. Inputs are
 * Uint8Array DER bytes; outputs are typed views or primitive values.
 */

// ─── Tag classes ─────────────────────────────────────────────────────────

export const TagClass = {
  UNIVERSAL: 0,
  APPLICATION: 1,
  CONTEXT: 2,
  PRIVATE: 3,
} as const;

export const UTag = {
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x10,
  SET: 0x11,
} as const;

// ─── TLV ─────────────────────────────────────────────────────────────────

export interface TLV {
  tagClass: number;
  constructed: boolean;
  tag: number;             // tag number (5 bits for short form, multibyte for long)
  length: number;          // content length
  valueOffset: number;     // offset into the buffer where value starts
  totalLength: number;     // tag + length-encoding + value bytes
}

export function parseTLV(buf: Uint8Array, offset = 0): TLV {
  if (offset >= buf.length) throw new Error("ASN.1: out of bounds");
  let i = offset;
  const first = buf[i++];
  const tagClass = (first >> 6) & 0x03;
  const constructed = (first & 0x20) !== 0;
  let tag = first & 0x1f;
  if (tag === 0x1f) {
    // Long-form tag
    tag = 0;
    let b: number;
    do {
      if (i >= buf.length) throw new Error("ASN.1: truncated long-form tag");
      b = buf[i++];
      tag = (tag << 7) | (b & 0x7f);
    } while ((b & 0x80) !== 0);
  }

  if (i >= buf.length) throw new Error("ASN.1: missing length");
  const lenByte = buf[i++];
  let length: number;
  if ((lenByte & 0x80) === 0) {
    length = lenByte;
  } else {
    const numBytes = lenByte & 0x7f;
    if (numBytes === 0) throw new Error("ASN.1: indefinite length not supported (DER required)");
    if (numBytes > 4) throw new Error("ASN.1: length too large");
    length = 0;
    for (let j = 0; j < numBytes; j++) {
      if (i >= buf.length) throw new Error("ASN.1: truncated length");
      length = (length << 8) | buf[i++];
    }
  }

  const valueOffset = i;
  const totalLength = valueOffset - offset + length;
  if (valueOffset + length > buf.length) throw new Error("ASN.1: value extends past buffer");

  return { tagClass, constructed, tag, length, valueOffset, totalLength };
}

// ─── Children / iteration ────────────────────────────────────────────────

export function children(buf: Uint8Array, parent: TLV): TLV[] {
  if (!parent.constructed) throw new Error("ASN.1: cannot read children of primitive TLV");
  const out: TLV[] = [];
  let i = parent.valueOffset;
  const end = parent.valueOffset + parent.length;
  while (i < end) {
    const child = parseTLV(buf, i);
    out.push(child);
    i += child.totalLength;
  }
  return out;
}

export function value(buf: Uint8Array, tlv: TLV): Uint8Array {
  return buf.subarray(tlv.valueOffset, tlv.valueOffset + tlv.length);
}

// ─── Primitives ──────────────────────────────────────────────────────────

export function parseInteger(buf: Uint8Array, tlv: TLV): bigint {
  const v = value(buf, tlv);
  if (v.length === 0) return 0n;
  let result = 0n;
  const negative = (v[0] & 0x80) !== 0;
  for (const byte of v) result = (result << 8n) | BigInt(byte);
  if (negative) {
    // Two's complement to negative
    const bits = BigInt(v.length * 8);
    result -= 1n << bits;
  }
  return result;
}

export function parseOID(buf: Uint8Array, tlv: TLV): string {
  const v = value(buf, tlv);
  if (v.length === 0) return "";
  const parts: number[] = [];
  const first = v[0];
  parts.push(Math.floor(first / 40));
  parts.push(first % 40);
  let acc = 0;
  for (let i = 1; i < v.length; i++) {
    const b = v[i];
    acc = (acc << 7) | (b & 0x7f);
    if ((b & 0x80) === 0) {
      parts.push(acc);
      acc = 0;
    }
  }
  return parts.join(".");
}

export function parseGeneralizedTime(buf: Uint8Array, tlv: TLV): Date {
  // Format: YYYYMMDDHHMMSS[.fff]Z
  const v = value(buf, tlv);
  const s = new TextDecoder().decode(v);
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(s);
  if (!m) throw new Error(`ASN.1: invalid GeneralizedTime: ${s}`);
  const [, y, mo, d, h, mi, se, frac] = m;
  const ms = frac ? Math.floor(parseFloat("0." + frac) * 1000) : 0;
  return new Date(Date.UTC(+y, +mo - 1, +d, +h, +mi, +se, ms));
}

export function parseOctetString(buf: Uint8Array, tlv: TLV): Uint8Array {
  return value(buf, tlv);
}

export function parseBitString(buf: Uint8Array, tlv: TLV): Uint8Array {
  // First byte is the number of unused bits in the last octet. We discard it
  // for our purposes (signature/key bit-strings are byte-aligned).
  const v = value(buf, tlv);
  if (v.length === 0) throw new Error("ASN.1: empty BIT STRING");
  return v.subarray(1);
}

// ─── Helpers for navigation ──────────────────────────────────────────────

export function expectTag(tlv: TLV, expectedClass: number, expectedTag: number, message: string): void {
  if (tlv.tagClass !== expectedClass || tlv.tag !== expectedTag) {
    throw new Error(
      `ASN.1: ${message} — expected class=${expectedClass} tag=${expectedTag}, got class=${tlv.tagClass} tag=${tlv.tag}`
    );
  }
}

export function expectUniversal(tlv: TLV, expectedTag: number, message: string): void {
  expectTag(tlv, TagClass.UNIVERSAL, expectedTag, message);
}

// ─── RFC 3161 TST extraction ─────────────────────────────────────────────

const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const OID_MESSAGE_DIGEST_ATTR = "1.2.840.113549.1.9.4";
const OID_CONTENT_TYPE_ATTR = "1.2.840.113549.1.9.3";

export interface TSTExtraction {
  /** SHA-256 (or other) of envelope-canonical-bytes that TSA stamped. */
  messageImprintHash: Uint8Array;
  /** Hash algorithm OID (typically 2.16.840.1.101.3.4.2.1 for SHA-256). */
  messageImprintAlgOid: string;
  /** TSA-attested production time. */
  genTime: Date;
  /** Nonce echoed from request, if any. */
  nonce?: bigint;
  /** TSTInfo DER bytes (what TSA signed via signedAttrs). */
  tstInfoDer: Uint8Array;
  /** TSA's certificate (DER-encoded). */
  tsaCertDer: Uint8Array;
  /** Signed attributes (DER) — these are what the TSA signature actually covers. */
  signedAttrsDer: Uint8Array;
  /** TSA's signature bytes. */
  signatureBytes: Uint8Array;
  /** Digest algorithm OID used in signedAttrs. */
  digestAlgOid: string;
  /** Signature algorithm OID. */
  signatureAlgOid: string;
}

/**
 * Parse an RFC 3161 TimeStampResp body to extract the TimeStampToken.
 * Returns the token's DER bytes (the entire ContentInfo).
 */
export function extractTokenFromResp(resp: Uint8Array): Uint8Array {
  // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL }
  const root = parseTLV(resp, 0);
  expectUniversal(root, UTag.SEQUENCE, "TimeStampResp root");
  const kids = children(resp, root);
  if (kids.length < 2) throw new Error("TimeStampResp missing token");

  // First child is PKIStatusInfo — verify status
  const statusInfo = kids[0];
  const statusKids = children(resp, statusInfo);
  const status = parseInteger(resp, statusKids[0]);
  if (status !== 0n && status !== 1n) {
    throw new Error(`TSA returned non-success PKIStatus: ${status}`);
  }

  // Second child is the TimeStampToken (a ContentInfo SEQUENCE)
  const token = kids[1];
  return resp.subarray(token.valueOffset - (token.totalLength - token.length), token.valueOffset + token.length);
}

/**
 * Parse a TimeStampToken (CMS ContentInfo) and extract everything we need.
 */
export function extractTSTInfo(tokenDer: Uint8Array): TSTExtraction {
  // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
  const root = parseTLV(tokenDer, 0);
  expectUniversal(root, UTag.SEQUENCE, "ContentInfo");
  const ciKids = children(tokenDer, root);
  const contentTypeOid = parseOID(tokenDer, ciKids[0]);
  if (contentTypeOid !== OID_SIGNED_DATA) {
    throw new Error(`TimeStampToken is not SignedData (got ${contentTypeOid})`);
  }

  // [0] EXPLICIT — unwrap one layer
  const contentWrapper = ciKids[1];
  const contentKids = children(tokenDer, contentWrapper);
  const signedData = contentKids[0];
  expectUniversal(signedData, UTag.SEQUENCE, "SignedData");

  const sdKids = children(tokenDer, signedData);
  // SignedData = { version, digestAlgorithms, encapContentInfo, [0] certs?, [1] crls?, signerInfos }
  // version = INTEGER, digestAlgorithms = SET, encapContentInfo = SEQUENCE,
  // certs = [0] IMPLICIT SET, signerInfos = SET
  let idx = 0;
  /* version */ idx++;
  /* digestAlgorithms */ idx++;
  const encapContentInfo = sdKids[idx++];

  // encapContentInfo = { eContentType OID, eContent [0] EXPLICIT OCTET STRING }
  const eciKids = children(tokenDer, encapContentInfo);
  const eContentTypeOid = parseOID(tokenDer, eciKids[0]);
  if (eContentTypeOid !== OID_TST_INFO) {
    throw new Error(`encapsulated content is not TSTInfo (got ${eContentTypeOid})`);
  }
  const eContentWrap = eciKids[1];
  const eContentKids = children(tokenDer, eContentWrap);
  const tstInfoOctets = eContentKids[0];
  const tstInfoDer = parseOctetString(tokenDer, tstInfoOctets);

  // Optional certs at [0]
  let tsaCertDer: Uint8Array | undefined;
  // Look ahead for context-class [0]
  while (idx < sdKids.length) {
    const k = sdKids[idx];
    if (k.tagClass === TagClass.CONTEXT && k.tag === 0) {
      const certs = children(tokenDer, k);
      if (certs.length === 0) throw new Error("certificates [0] is empty");
      // First cert is the TSA's signing cert (typically). Capture the entire DER.
      const cert = certs[0];
      tsaCertDer = tokenDer.subarray(
        cert.valueOffset - (cert.totalLength - cert.length),
        cert.valueOffset + cert.length
      );
      idx++;
      break;
    } else if (k.tagClass === TagClass.CONTEXT && k.tag === 1) {
      // crls — skip
      idx++;
    } else {
      break;
    }
  }
  if (!tsaCertDer) throw new Error("TimeStampToken does not embed a TSA certificate");

  // signerInfos = SET OF SignerInfo
  const signerInfos = sdKids[idx];
  expectUniversal(signerInfos, UTag.SET, "signerInfos");
  const signerInfoList = children(tokenDer, signerInfos);
  if (signerInfoList.length === 0) throw new Error("no SignerInfo");
  const signerInfo = signerInfoList[0];
  const siKids = children(tokenDer, signerInfo);

  // SignerInfo = { version, sid (issuerAndSerialNumber|subjectKeyIdentifier),
  //                digestAlgorithm, [0] signedAttrs?, signatureAlgorithm,
  //                signature, [1] unsignedAttrs? }
  let siIdx = 0;
  /* version */ siIdx++;
  /* sid */ siIdx++;
  const digestAlg = siKids[siIdx++];
  const digestAlgOid = parseOID(tokenDer, children(tokenDer, digestAlg)[0]);

  let signedAttrsDer: Uint8Array | undefined;
  if (siKids[siIdx].tagClass === TagClass.CONTEXT && siKids[siIdx].tag === 0) {
    // signedAttrs are [0] IMPLICIT — for signature purposes we re-encode as SET.
    const sa = siKids[siIdx];
    // SET tag is 0x31; replace context-implicit tag 0xa0 with SET 0x31.
    const inner = tokenDer.subarray(sa.valueOffset, sa.valueOffset + sa.length);
    // Build proper DER encoding: SET (0x31) + length + inner
    signedAttrsDer = encodeSet(inner);
    siIdx++;
  } else {
    throw new Error("SignerInfo missing signedAttrs (required for RFC 3161)");
  }

  const sigAlg = siKids[siIdx++];
  const signatureAlgOid = parseOID(tokenDer, children(tokenDer, sigAlg)[0]);
  const signatureOctet = siKids[siIdx++];
  const signatureBytes = parseOctetString(tokenDer, signatureOctet);

  // Now parse TSTInfo to pull messageImprint, genTime, nonce
  const tstInfoTLV = parseTLV(tstInfoDer, 0);
  expectUniversal(tstInfoTLV, UTag.SEQUENCE, "TSTInfo");
  const tiKids = children(tstInfoDer, tstInfoTLV);
  // version, policy, messageImprint, serialNumber, genTime, [accuracy], [ordering], [nonce], ...
  let tiIdx = 0;
  /* version */ tiIdx++;
  /* policy */ tiIdx++;
  const messageImprint = tiKids[tiIdx++];
  const miKids = children(tstInfoDer, messageImprint);
  const miAlg = miKids[0];
  const messageImprintAlgOid = parseOID(tstInfoDer, children(tstInfoDer, miAlg)[0]);
  const messageImprintHash = parseOctetString(tstInfoDer, miKids[1]);
  /* serialNumber */ tiIdx++;
  const genTime = parseGeneralizedTime(tstInfoDer, tiKids[tiIdx++]);

  let nonce: bigint | undefined;
  while (tiIdx < tiKids.length) {
    const k = tiKids[tiIdx];
    if (k.tagClass === TagClass.UNIVERSAL && k.tag === UTag.INTEGER) {
      nonce = parseInteger(tstInfoDer, k);
      break;
    }
    tiIdx++;
  }

  return {
    messageImprintHash,
    messageImprintAlgOid,
    genTime,
    nonce,
    tstInfoDer,
    tsaCertDer,
    signedAttrsDer,
    signatureBytes,
    digestAlgOid,
    signatureAlgOid,
  };
}

// ─── Minimal DER encoding helpers (for re-encoding signedAttrs as SET) ───

function encodeLength(len: number): Uint8Array {
  if (len < 0x80) return new Uint8Array([len]);
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function encodeSet(content: Uint8Array): Uint8Array {
  const len = encodeLength(content.length);
  const out = new Uint8Array(1 + len.length + content.length);
  out[0] = 0x31; // SET, constructed
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
}

// ─── Cert SPKI extraction (for Web Crypto importKey) ─────────────────────

/**
 * Extract subjectPublicKeyInfo (SPKI) DER bytes from an X.509 certificate.
 * Web Crypto's `importKey("spki", ...)` consumes this directly.
 */
export function extractCertSPKI(certDer: Uint8Array): Uint8Array {
  // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
  const root = parseTLV(certDer, 0);
  expectUniversal(root, UTag.SEQUENCE, "Certificate");
  const certKids = children(certDer, root);
  const tbs = certKids[0];
  expectUniversal(tbs, UTag.SEQUENCE, "TBSCertificate");

  // TBSCertificate ::= SEQUENCE {
  //   [0] EXPLICIT version DEFAULT v1, serialNumber, signature,
  //   issuer, validity, subject, subjectPublicKeyInfo, ... }
  const tbsKids = children(certDer, tbs);
  let idx = 0;
  // Skip version if present
  if (tbsKids[0].tagClass === TagClass.CONTEXT && tbsKids[0].tag === 0) idx++;
  /* serialNumber */ idx++;
  /* signature */ idx++;
  /* issuer */ idx++;
  /* validity */ idx++;
  /* subject */ idx++;
  const spki = tbsKids[idx];

  return certDer.subarray(
    spki.valueOffset - (spki.totalLength - spki.length),
    spki.valueOffset + spki.length
  );
}
