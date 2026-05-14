/**
 * @lexitsp/sdk v3 · RFC 3161 TSA client
 *
 * Sequential multi-TSA fallback per spec decision Q3.5/A.
 * Sends TimeStampReq, receives TimeStampResp, returns base64-encoded token
 * plus TSA-attested time and which TSA actually responded.
 */

import { extractTokenFromResp, extractTSTInfo } from "./asn1";

const HASH_ALG_OID_SHA256 = "2.16.840.1.101.3.4.2.1";

// ─── DER encoding helpers (just enough for TimeStampReq) ─────────────────

function encodeLen(len: number): number[] {
  if (len < 0x80) return [len];
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

function encodeTLV(tag: number, content: number[] | Uint8Array): number[] {
  const c = Array.isArray(content) ? content : Array.from(content);
  return [tag, ...encodeLen(c.length), ...c];
}

function encodeOID(oid: string): number[] {
  const parts = oid.split(".").map((p) => parseInt(p, 10));
  if (parts.length < 2) throw new Error(`invalid OID: ${oid}`);
  const out: number[] = [parts[0] * 40 + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let n = parts[i];
    const buf: number[] = [];
    do {
      buf.unshift(n & 0x7f);
      n >>>= 7;
    } while (n > 0);
    for (let j = 0; j < buf.length - 1; j++) buf[j] |= 0x80;
    out.push(...buf);
  }
  return encodeTLV(0x06, out);
}

function encodeInteger(n: number | bigint): number[] {
  // Positive only (we use it for version=1 and nonce). Add leading 0 if MSB set.
  let big = typeof n === "bigint" ? n : BigInt(n);
  if (big < 0n) throw new Error("negative INTEGER not supported");
  if (big === 0n) return encodeTLV(0x02, [0]);
  const bytes: number[] = [];
  while (big > 0n) {
    bytes.unshift(Number(big & 0xffn));
    big >>= 8n;
  }
  if (bytes[0] & 0x80) bytes.unshift(0);
  return encodeTLV(0x02, bytes);
}

function encodeOctetString(data: Uint8Array): number[] {
  return encodeTLV(0x04, Array.from(data));
}

function encodeSequence(content: number[]): number[] {
  return encodeTLV(0x30, content);
}

function encodeNull(): number[] {
  return [0x05, 0x00];
}

function encodeBoolean(v: boolean): number[] {
  return [0x01, 0x01, v ? 0xff : 0x00];
}

// ─── TimeStampReq builder ────────────────────────────────────────────────

export interface BuildTimeStampReqOptions {
  hash: Uint8Array;     // SHA-256 of the data being timestamped
  nonce: bigint;
  certReq: boolean;     // ask TSA to include cert in response
}

export function buildTimeStampReq(opts: BuildTimeStampReqOptions): Uint8Array {
  // TimeStampReq ::= SEQUENCE {
  //   version INTEGER (v1=1),
  //   messageImprint MessageImprint,
  //   reqPolicy TSAPolicyId OPTIONAL,
  //   nonce INTEGER OPTIONAL,
  //   certReq BOOLEAN DEFAULT FALSE
  // }
  // MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
  // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY DEFINED BY algorithm OPTIONAL }

  const algIdent = encodeSequence([...encodeOID(HASH_ALG_OID_SHA256), ...encodeNull()]);
  const messageImprint = encodeSequence([...algIdent, ...encodeOctetString(opts.hash)]);

  const body: number[] = [];
  body.push(...encodeInteger(1));
  body.push(...messageImprint);
  body.push(...encodeInteger(opts.nonce));
  if (opts.certReq) body.push(...encodeBoolean(true));

  return new Uint8Array(encodeSequence(body));
}

// ─── Random nonce ─────────────────────────────────────────────────────────

function randomNonce(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  // Ensure positive (clear top bit) for ASN.1 INTEGER simplicity
  return n & 0x7fffffffffffffffn;
}

// ─── Stamp (the public API) ──────────────────────────────────────────────

export interface TsaClientOptions {
  /** TSA URLs in priority order; first-success-wins. */
  urls: string[];
  /** Per-TSA timeout in ms. Default 10_000. */
  timeoutMs?: number;
  /** Override fetch (testing). */
  fetch?: typeof globalThis.fetch;
}

export interface TsaStampResult {
  /** Base64-encoded TimeStampToken (the entire ContentInfo). */
  token: string;
  /** URL of the TSA that successfully responded. */
  tsaUrl: string;
  /** TSA-attested production time (ISO8601). */
  genTime: string;
}

export async function stampHash(
  hash: Uint8Array,
  opts: TsaClientOptions
): Promise<TsaStampResult> {
  if (opts.urls.length === 0) {
    throw new Error("stampHash: no TSA URLs configured");
  }

  const fetchFn = opts.fetch ?? globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const errors: string[] = [];

  for (const url of opts.urls) {
    const nonce = randomNonce();
    const req = buildTimeStampReq({ hash, nonce, certReq: true });

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      let response: Response;
      try {
        response = await fetchFn(url, {
          method: "POST",
          headers: { "Content-Type": "application/timestamp-query" },
          body: req as unknown as BodyInit,
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timer);
      }

      if (!response.ok) {
        errors.push(`${url}: HTTP ${response.status}`);
        continue;
      }

      const respBody = new Uint8Array(await response.arrayBuffer());
      const tokenDer = extractTokenFromResp(respBody);
      const tst = extractTSTInfo(tokenDer);

      // Verify nonce echo (replay protection)
      if (tst.nonce === undefined || tst.nonce !== nonce) {
        errors.push(`${url}: nonce mismatch (replay protection failed)`);
        continue;
      }

      // Verify hash matches
      if (!byteArraysEqual(tst.messageImprintHash, hash)) {
        errors.push(`${url}: messageImprint hash mismatch`);
        continue;
      }

      let bin = "";
      for (const b of tokenDer) bin += String.fromCharCode(b);
      return {
        token: btoa(bin),
        tsaUrl: url,
        genTime: tst.genTime.toISOString(),
      };
    } catch (e) {
      errors.push(`${url}: ${(e as Error).message}`);
      continue;
    }
  }

  throw new Error(`stampHash: all TSAs failed. Errors: ${errors.join(" | ")}`);
}

function byteArraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
