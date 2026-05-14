import {
  canonicalize,
  checkRevocation,
  importPublicKeyJwk,
  verify
} from "./chunk-CCJVYHGK.js";

// src/v3/types.ts
var TSP_V3_VERSION = "3.0";

// src/v3/canonical-hash.ts
var encoder = new TextEncoder();
async function sha256Hex(input) {
  const buf = await crypto.subtle.digest("SHA-256", encoder.encode(input));
  const bytes = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}
async function sha256Bytes(input) {
  const buf = await crypto.subtle.digest("SHA-256", input);
  return new Uint8Array(buf);
}

// src/v3/asn1.ts
var TagClass = {
  UNIVERSAL: 0,
  APPLICATION: 1,
  CONTEXT: 2,
  PRIVATE: 3
};
var UTag = {
  INTEGER: 2,
  BIT_STRING: 3,
  OCTET_STRING: 4,
  NULL: 5,
  OID: 6,
  UTF8_STRING: 12,
  PRINTABLE_STRING: 19,
  IA5_STRING: 22,
  UTC_TIME: 23,
  GENERALIZED_TIME: 24,
  SEQUENCE: 16,
  SET: 17
};
function parseTLV(buf, offset = 0) {
  if (offset >= buf.length) throw new Error("ASN.1: out of bounds");
  let i = offset;
  const first = buf[i++];
  const tagClass = first >> 6 & 3;
  const constructed = (first & 32) !== 0;
  let tag = first & 31;
  if (tag === 31) {
    tag = 0;
    let b;
    do {
      if (i >= buf.length) throw new Error("ASN.1: truncated long-form tag");
      b = buf[i++];
      tag = tag << 7 | b & 127;
    } while ((b & 128) !== 0);
  }
  if (i >= buf.length) throw new Error("ASN.1: missing length");
  const lenByte = buf[i++];
  let length;
  if ((lenByte & 128) === 0) {
    length = lenByte;
  } else {
    const numBytes = lenByte & 127;
    if (numBytes === 0) throw new Error("ASN.1: indefinite length not supported (DER required)");
    if (numBytes > 4) throw new Error("ASN.1: length too large");
    length = 0;
    for (let j = 0; j < numBytes; j++) {
      if (i >= buf.length) throw new Error("ASN.1: truncated length");
      length = length << 8 | buf[i++];
    }
  }
  const valueOffset = i;
  const totalLength = valueOffset - offset + length;
  if (valueOffset + length > buf.length) throw new Error("ASN.1: value extends past buffer");
  return { tagClass, constructed, tag, length, valueOffset, totalLength };
}
function children(buf, parent) {
  if (!parent.constructed) throw new Error("ASN.1: cannot read children of primitive TLV");
  const out = [];
  let i = parent.valueOffset;
  const end = parent.valueOffset + parent.length;
  while (i < end) {
    const child = parseTLV(buf, i);
    out.push(child);
    i += child.totalLength;
  }
  return out;
}
function value(buf, tlv) {
  return buf.subarray(tlv.valueOffset, tlv.valueOffset + tlv.length);
}
function parseInteger(buf, tlv) {
  const v = value(buf, tlv);
  if (v.length === 0) return 0n;
  let result = 0n;
  const negative = (v[0] & 128) !== 0;
  for (const byte of v) result = result << 8n | BigInt(byte);
  if (negative) {
    const bits = BigInt(v.length * 8);
    result -= 1n << bits;
  }
  return result;
}
function parseOID(buf, tlv) {
  const v = value(buf, tlv);
  if (v.length === 0) return "";
  const parts = [];
  const first = v[0];
  parts.push(Math.floor(first / 40));
  parts.push(first % 40);
  let acc = 0;
  for (let i = 1; i < v.length; i++) {
    const b = v[i];
    acc = acc << 7 | b & 127;
    if ((b & 128) === 0) {
      parts.push(acc);
      acc = 0;
    }
  }
  return parts.join(".");
}
function parseGeneralizedTime(buf, tlv) {
  const v = value(buf, tlv);
  const s = new TextDecoder().decode(v);
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(s);
  if (!m) throw new Error(`ASN.1: invalid GeneralizedTime: ${s}`);
  const [, y, mo, d, h, mi, se, frac] = m;
  const ms = frac ? Math.floor(parseFloat("0." + frac) * 1e3) : 0;
  return new Date(Date.UTC(+y, +mo - 1, +d, +h, +mi, +se, ms));
}
function parseOctetString(buf, tlv) {
  return value(buf, tlv);
}
function expectTag(tlv, expectedClass, expectedTag, message) {
  if (tlv.tagClass !== expectedClass || tlv.tag !== expectedTag) {
    throw new Error(
      `ASN.1: ${message} \u2014 expected class=${expectedClass} tag=${expectedTag}, got class=${tlv.tagClass} tag=${tlv.tag}`
    );
  }
}
function expectUniversal(tlv, expectedTag, message) {
  expectTag(tlv, TagClass.UNIVERSAL, expectedTag, message);
}
var OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
var OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";
function extractTokenFromResp(resp) {
  const root = parseTLV(resp, 0);
  expectUniversal(root, UTag.SEQUENCE, "TimeStampResp root");
  const kids = children(resp, root);
  if (kids.length < 2) throw new Error("TimeStampResp missing token");
  const statusInfo = kids[0];
  const statusKids = children(resp, statusInfo);
  const status = parseInteger(resp, statusKids[0]);
  if (status !== 0n && status !== 1n) {
    throw new Error(`TSA returned non-success PKIStatus: ${status}`);
  }
  const token = kids[1];
  return resp.subarray(token.valueOffset - (token.totalLength - token.length), token.valueOffset + token.length);
}
function extractTSTInfo(tokenDer) {
  const root = parseTLV(tokenDer, 0);
  expectUniversal(root, UTag.SEQUENCE, "ContentInfo");
  const ciKids = children(tokenDer, root);
  const contentTypeOid = parseOID(tokenDer, ciKids[0]);
  if (contentTypeOid !== OID_SIGNED_DATA) {
    throw new Error(`TimeStampToken is not SignedData (got ${contentTypeOid})`);
  }
  const contentWrapper = ciKids[1];
  const contentKids = children(tokenDer, contentWrapper);
  const signedData = contentKids[0];
  expectUniversal(signedData, UTag.SEQUENCE, "SignedData");
  const sdKids = children(tokenDer, signedData);
  let idx = 0;
  idx++;
  idx++;
  const encapContentInfo = sdKids[idx++];
  const eciKids = children(tokenDer, encapContentInfo);
  const eContentTypeOid = parseOID(tokenDer, eciKids[0]);
  if (eContentTypeOid !== OID_TST_INFO) {
    throw new Error(`encapsulated content is not TSTInfo (got ${eContentTypeOid})`);
  }
  const eContentWrap = eciKids[1];
  const eContentKids = children(tokenDer, eContentWrap);
  const tstInfoOctets = eContentKids[0];
  const tstInfoDer = parseOctetString(tokenDer, tstInfoOctets);
  let tsaCertDer;
  while (idx < sdKids.length) {
    const k = sdKids[idx];
    if (k.tagClass === TagClass.CONTEXT && k.tag === 0) {
      const certs = children(tokenDer, k);
      if (certs.length === 0) throw new Error("certificates [0] is empty");
      const cert = certs[0];
      tsaCertDer = tokenDer.subarray(
        cert.valueOffset - (cert.totalLength - cert.length),
        cert.valueOffset + cert.length
      );
      idx++;
      break;
    } else if (k.tagClass === TagClass.CONTEXT && k.tag === 1) {
      idx++;
    } else {
      break;
    }
  }
  if (!tsaCertDer) throw new Error("TimeStampToken does not embed a TSA certificate");
  const signerInfos = sdKids[idx];
  expectUniversal(signerInfos, UTag.SET, "signerInfos");
  const signerInfoList = children(tokenDer, signerInfos);
  if (signerInfoList.length === 0) throw new Error("no SignerInfo");
  const signerInfo = signerInfoList[0];
  const siKids = children(tokenDer, signerInfo);
  let siIdx = 0;
  siIdx++;
  siIdx++;
  const digestAlg = siKids[siIdx++];
  const digestAlgOid = parseOID(tokenDer, children(tokenDer, digestAlg)[0]);
  let signedAttrsDer;
  if (siKids[siIdx].tagClass === TagClass.CONTEXT && siKids[siIdx].tag === 0) {
    const sa = siKids[siIdx];
    const inner = tokenDer.subarray(sa.valueOffset, sa.valueOffset + sa.length);
    signedAttrsDer = encodeSet(inner);
    siIdx++;
  } else {
    throw new Error("SignerInfo missing signedAttrs (required for RFC 3161)");
  }
  const sigAlg = siKids[siIdx++];
  const signatureAlgOid = parseOID(tokenDer, children(tokenDer, sigAlg)[0]);
  const signatureOctet = siKids[siIdx++];
  const signatureBytes = parseOctetString(tokenDer, signatureOctet);
  const tstInfoTLV = parseTLV(tstInfoDer, 0);
  expectUniversal(tstInfoTLV, UTag.SEQUENCE, "TSTInfo");
  const tiKids = children(tstInfoDer, tstInfoTLV);
  let tiIdx = 0;
  tiIdx++;
  tiIdx++;
  const messageImprint = tiKids[tiIdx++];
  const miKids = children(tstInfoDer, messageImprint);
  const miAlg = miKids[0];
  const messageImprintAlgOid = parseOID(tstInfoDer, children(tstInfoDer, miAlg)[0]);
  const messageImprintHash = parseOctetString(tstInfoDer, miKids[1]);
  tiIdx++;
  const genTime = parseGeneralizedTime(tstInfoDer, tiKids[tiIdx++]);
  let nonce;
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
    signatureAlgOid
  };
}
function encodeLength(len) {
  if (len < 128) return new Uint8Array([len]);
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 255);
    n >>>= 8;
  }
  return new Uint8Array([128 | bytes.length, ...bytes]);
}
function encodeSet(content) {
  const len = encodeLength(content.length);
  const out = new Uint8Array(1 + len.length + content.length);
  out[0] = 49;
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
}
function extractCertSPKI(certDer) {
  const root = parseTLV(certDer, 0);
  expectUniversal(root, UTag.SEQUENCE, "Certificate");
  const certKids = children(certDer, root);
  const tbs = certKids[0];
  expectUniversal(tbs, UTag.SEQUENCE, "TBSCertificate");
  const tbsKids = children(certDer, tbs);
  let idx = 0;
  if (tbsKids[0].tagClass === TagClass.CONTEXT && tbsKids[0].tag === 0) idx++;
  idx++;
  idx++;
  idx++;
  idx++;
  idx++;
  const spki = tbsKids[idx];
  return certDer.subarray(
    spki.valueOffset - (spki.totalLength - spki.length),
    spki.valueOffset + spki.length
  );
}

// src/v3/tsa.ts
var HASH_ALG_OID_SHA256 = "2.16.840.1.101.3.4.2.1";
function encodeLen(len) {
  if (len < 128) return [len];
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 255);
    n >>>= 8;
  }
  return [128 | bytes.length, ...bytes];
}
function encodeTLV(tag, content) {
  const c = Array.isArray(content) ? content : Array.from(content);
  return [tag, ...encodeLen(c.length), ...c];
}
function encodeOID(oid) {
  const parts = oid.split(".").map((p) => parseInt(p, 10));
  if (parts.length < 2) throw new Error(`invalid OID: ${oid}`);
  const out = [parts[0] * 40 + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let n = parts[i];
    const buf = [];
    do {
      buf.unshift(n & 127);
      n >>>= 7;
    } while (n > 0);
    for (let j = 0; j < buf.length - 1; j++) buf[j] |= 128;
    out.push(...buf);
  }
  return encodeTLV(6, out);
}
function encodeInteger(n) {
  let big = typeof n === "bigint" ? n : BigInt(n);
  if (big < 0n) throw new Error("negative INTEGER not supported");
  if (big === 0n) return encodeTLV(2, [0]);
  const bytes = [];
  while (big > 0n) {
    bytes.unshift(Number(big & 0xffn));
    big >>= 8n;
  }
  if (bytes[0] & 128) bytes.unshift(0);
  return encodeTLV(2, bytes);
}
function encodeOctetString(data) {
  return encodeTLV(4, Array.from(data));
}
function encodeSequence(content) {
  return encodeTLV(48, content);
}
function encodeNull() {
  return [5, 0];
}
function encodeBoolean(v) {
  return [1, 1, v ? 255 : 0];
}
function buildTimeStampReq(opts) {
  const algIdent = encodeSequence([...encodeOID(HASH_ALG_OID_SHA256), ...encodeNull()]);
  const messageImprint = encodeSequence([...algIdent, ...encodeOctetString(opts.hash)]);
  const body = [];
  body.push(...encodeInteger(1));
  body.push(...messageImprint);
  body.push(...encodeInteger(opts.nonce));
  if (opts.certReq) body.push(...encodeBoolean(true));
  return new Uint8Array(encodeSequence(body));
}
function randomNonce() {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let n = 0n;
  for (const b of bytes) n = n << 8n | BigInt(b);
  return n & 0x7fffffffffffffffn;
}
async function stampHash(hash, opts) {
  if (opts.urls.length === 0) {
    throw new Error("stampHash: no TSA URLs configured");
  }
  const fetchFn = opts.fetch ?? globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? 1e4;
  const errors = [];
  for (const url of opts.urls) {
    const nonce = randomNonce();
    const req = buildTimeStampReq({ hash, nonce, certReq: true });
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      let response;
      try {
        response = await fetchFn(url, {
          method: "POST",
          headers: { "Content-Type": "application/timestamp-query" },
          body: req,
          signal: controller.signal
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
      if (tst.nonce === void 0 || tst.nonce !== nonce) {
        errors.push(`${url}: nonce mismatch (replay protection failed)`);
        continue;
      }
      if (!byteArraysEqual(tst.messageImprintHash, hash)) {
        errors.push(`${url}: messageImprint hash mismatch`);
        continue;
      }
      let bin = "";
      for (const b of tokenDer) bin += String.fromCharCode(b);
      return {
        token: btoa(bin),
        tsaUrl: url,
        genTime: tst.genTime.toISOString()
      };
    } catch (e) {
      errors.push(`${url}: ${e.message}`);
      continue;
    }
  }
  throw new Error(`stampHash: all TSAs failed. Errors: ${errors.join(" | ")}`);
}
function byteArraysEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// src/v3/envelope.ts
var TSA_PLACEHOLDER_TOKEN = "__phase1__";
var TSA_PLACEHOLDER_URL = "https://placeholder.invalid/phase1";
function uuidv7() {
  const ts = BigInt(Date.now());
  const hex = ts.toString(16).padStart(12, "0");
  const rand = crypto.getRandomValues(new Uint8Array(10));
  rand[0] = rand[0] & 15 | 112;
  rand[2] = rand[2] & 63 | 128;
  let randHex = "";
  for (let i = 0; i < rand.length; i++) randHex += rand[i].toString(16).padStart(2, "0");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    randHex.slice(0, 4),
    randHex.slice(4, 8),
    randHex.slice(8, 20)
  ].join("-");
}
var textEncoder = new TextEncoder();
function bytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function hexToBytes(hex) {
  if (hex.length % 2) throw new Error("hex string must be even");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function isProduction() {
  return typeof process !== "undefined" && process.env && process.env.NODE_ENV === "production";
}
async function wrap(input, opts) {
  const localNow = (opts.now ?? /* @__PURE__ */ new Date()).toISOString();
  const contentHash = await sha256Hex(canonicalize(input.value));
  const envelope = {
    tsp: TSP_V3_VERSION,
    content: { type: input.type, value: input.value, hash: contentHash },
    declaration: opts.declaration,
    process: opts.process,
    alignment: opts.alignment,
    timestamp: {
      claimed: localNow,
      tsaToken: TSA_PLACEHOLDER_TOKEN,
      tsaUrl: TSA_PLACEHOLDER_URL
    },
    ledger: { id: uuidv7(), prevHash: opts.prevHash, hash: "" },
    signatures: []
  };
  const sigDomain = {
    tsp: envelope.tsp,
    content: envelope.content,
    declaration: envelope.declaration,
    process: envelope.process,
    alignment: envelope.alignment,
    timestamp: { claimed: envelope.timestamp.claimed, tsaUrl: envelope.timestamp.tsaUrl },
    ledger: { id: envelope.ledger.id, prevHash: envelope.ledger.prevHash }
  };
  const sigBytes = await opts.signer.sign(textEncoder.encode(canonicalize(sigDomain)));
  const signatureEntry = {
    role: "instance",
    algorithm: "ed25519",
    keyRef: opts.signer.keyRef,
    signature: bytesToBase64(sigBytes),
    certChain: opts.signer.certChain
  };
  envelope.signatures = [signatureEntry];
  if (!opts.skipTsa) {
    const tsaUrls = opts.tsaUrls ?? defaultTsaUrls();
    if (tsaUrls.length === 0) {
      console.warn(
        "[@lexitsp/sdk/v3] wrap() running with no TSA configured. Envelope will use placeholder tsaToken. Configure tsaUrls in production."
      );
    } else {
      const tsaInputDomain = {
        tsp: envelope.tsp,
        content: envelope.content,
        declaration: envelope.declaration,
        process: envelope.process,
        alignment: envelope.alignment,
        timestamp: { claimed: envelope.timestamp.claimed, tsaUrl: envelope.timestamp.tsaUrl },
        ledger: { id: envelope.ledger.id, prevHash: envelope.ledger.prevHash },
        signatures: envelope.signatures
      };
      const tsaInputHash = hexToBytes(await sha256Hex(canonicalize(tsaInputDomain)));
      const stampOpts = { urls: tsaUrls };
      if (opts.tsaTimeoutMs !== void 0) stampOpts.timeoutMs = opts.tsaTimeoutMs;
      if (opts.fetch !== void 0) stampOpts.fetch = opts.fetch;
      const stamp = await stampHash(tsaInputHash, stampOpts);
      envelope.timestamp.tsaToken = stamp.token;
      envelope.timestamp.tsaUrl = stamp.tsaUrl;
      envelope.timestamp.claimed = stamp.genTime;
    }
  }
  const ledgerDomain = {
    tsp: envelope.tsp,
    content: envelope.content,
    declaration: envelope.declaration,
    process: envelope.process,
    alignment: envelope.alignment,
    timestamp: envelope.timestamp,
    signatures: envelope.signatures,
    ledger: { id: envelope.ledger.id, prevHash: envelope.ledger.prevHash }
  };
  envelope.ledger.hash = await sha256Hex(canonicalize(ledgerDomain));
  if (opts.riskSink) {
    void postToRiskSink(envelope, opts.riskSink);
  }
  return envelope;
}
async function postToRiskSink(envelope, cfg) {
  const onError = cfg.onError ?? "warn";
  const fetchImpl = cfg.fetch ?? globalThis.fetch;
  try {
    const res = await fetchImpl(cfg.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${cfg.apiKey}`
      },
      body: JSON.stringify(envelope)
    });
    if (!res.ok) {
      throw new Error(`riskSink POST failed: ${res.status} ${res.statusText}`);
    }
  } catch (err) {
    if (onError === "throw") throw err;
    if (onError === "warn") {
      console.warn(
        `[@lexitsp/sdk/v3] riskSink delivery failed: ${err.message}`
      );
    }
  }
}
function defaultTsaUrls() {
  if (isProduction()) {
    throw new Error(
      "wrap() requires explicit TSA configuration in production. Set { tsaUrls: [...] } in WrapOptions, or set { skipTsa: true } for legacy behavior."
    );
  }
  return [];
}

// src/v3/verify.ts
var PASS = (detail) => ({ status: "passed", detail });
var FAIL = (detail, evidence) => ({
  status: "failed",
  detail,
  evidence
});
var SKIP = (detail) => ({ status: "skipped", detail });
var textEncoder2 = new TextEncoder();
async function verifyLocal(envelope, opts) {
  const checks = {
    schema: SKIP("not yet checked"),
    contentHash: SKIP("not yet checked"),
    ledgerHash: SKIP("not yet checked"),
    manifestFetch: SKIP("local-only mode: manifest fetch not performed"),
    rootSignature: SKIP("local-only mode: root signature not verified"),
    certChain: SKIP("local-only mode: cert chain not validated"),
    certValidity: SKIP("local-only mode: cert validity not checked"),
    revocation: SKIP("local-only mode: revocation not checked"),
    tsa: SKIP("local-only mode: TSA token not verified"),
    signatures: []
  };
  const warnings = [];
  if (envelope.tsp !== TSP_V3_VERSION) {
    checks.schema = FAIL(`expected tsp="${TSP_V3_VERSION}", got "${envelope.tsp}"`);
  } else if (!envelope.content || !envelope.signatures || envelope.signatures.length === 0) {
    checks.schema = FAIL("envelope missing required fields");
  } else {
    checks.schema = PASS("schema is well-formed");
  }
  const expectedContentHash = await sha256Hex(canonicalize(envelope.content.value));
  if (expectedContentHash === envelope.content.hash) {
    checks.contentHash = PASS("content hash matches canonical(value)");
  } else {
    checks.contentHash = FAIL(
      `content hash mismatch: claimed ${envelope.content.hash}, computed ${expectedContentHash}`
    );
  }
  const ledgerDomain = {
    tsp: envelope.tsp,
    content: envelope.content,
    declaration: envelope.declaration,
    process: envelope.process,
    alignment: envelope.alignment,
    timestamp: envelope.timestamp,
    signatures: envelope.signatures,
    ledger: { id: envelope.ledger.id, prevHash: envelope.ledger.prevHash }
  };
  const expectedLedgerHash = await sha256Hex(canonicalize(ledgerDomain));
  if (expectedLedgerHash === envelope.ledger.hash) {
    checks.ledgerHash = PASS("ledger hash matches canonical(envelope \u2212 ledger.hash)");
  } else {
    checks.ledgerHash = FAIL(
      `ledger hash mismatch: claimed ${envelope.ledger.hash}, computed ${expectedLedgerHash}`
    );
  }
  for (const sig of envelope.signatures) {
    if (sig.algorithm !== "ed25519") {
      checks.signatures.push(FAIL(`unsupported algorithm: ${sig.algorithm}`));
      continue;
    }
    const sigDomain = {
      tsp: envelope.tsp,
      content: envelope.content,
      declaration: envelope.declaration,
      process: envelope.process,
      alignment: envelope.alignment,
      timestamp: { claimed: envelope.timestamp.claimed, tsaUrl: envelope.timestamp.tsaUrl },
      ledger: { id: envelope.ledger.id, prevHash: envelope.ledger.prevHash }
    };
    let publicKey;
    try {
      publicKey = await importPublicKeyJwk(opts.knownPublicKey);
    } catch (e) {
      checks.signatures.push(FAIL(`could not import known public key: ${String(e)}`));
      continue;
    }
    let sigBytes;
    try {
      sigBytes = Uint8Array.from(atob(sig.signature), (c) => c.charCodeAt(0));
    } catch (e) {
      checks.signatures.push(FAIL(`signature is not valid base64: ${String(e)}`));
      continue;
    }
    const ok = await verify(
      publicKey,
      sigBytes,
      textEncoder2.encode(canonicalize(sigDomain))
    );
    checks.signatures.push(
      ok ? PASS(`signature valid (role=${sig.role}, algorithm=${sig.algorithm})`) : FAIL(`signature invalid (role=${sig.role}, algorithm=${sig.algorithm})`)
    );
  }
  warnings.push(
    "local-only verify: manifest, cert-chain, TSA, and revocation checks are not performed in Phase 1"
  );
  const requiredChecks = [
    checks.schema,
    checks.contentHash,
    checks.ledgerHash,
    ...checks.signatures
  ];
  const valid = requiredChecks.every((c) => c.status === "passed");
  return { valid, envelope, checks, warnings };
}

// src/v3/manifest-verify.ts
var enc = new TextEncoder();
function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
async function verifyManifestSignature(manifest) {
  const { rootSignatureOverManifest, ...unsigned } = manifest;
  let pubKey;
  let sigBytes;
  try {
    pubKey = await importPublicKeyJwk(manifest.rootKey);
    sigBytes = base64ToBytes(rootSignatureOverManifest);
  } catch {
    return false;
  }
  try {
    return await verify(pubKey, sigBytes, enc.encode(canonicalize(unsigned)));
  } catch {
    return false;
  }
}
async function verifyInstanceCert(cert, rootKey) {
  const { rootSignature, ...payload } = cert;
  let pubKey;
  let sigBytes;
  try {
    pubKey = await importPublicKeyJwk(rootKey);
    sigBytes = base64ToBytes(rootSignature);
  } catch {
    return false;
  }
  try {
    return await verify(pubKey, sigBytes, enc.encode(canonicalize(payload)));
  } catch {
    return false;
  }
}

// src/v3/manifest-fetch.ts
var DEFAULT_TTL_MS = 60 * 60 * 1e3;
var DEFAULT_MAX_ENTRIES = 100;
var cache = /* @__PURE__ */ new Map();
function clearManifestCache() {
  cache.clear();
}
function evictIfNeeded(maxEntries) {
  if (cache.size <= maxEntries) return;
  const entries = Array.from(cache.entries()).sort((a, b) => a[1].fetchedAt - b[1].fetchedAt);
  const toRemove = entries.length - maxEntries;
  for (let i = 0; i < toRemove; i++) cache.delete(entries[i][0]);
}
async function fetchManifest(url, opts = {}) {
  const fetchFn = opts.fetch ?? globalThis.fetch;
  const ttl = opts.ttlMs ?? DEFAULT_TTL_MS;
  const maxEntries = opts.maxEntries ?? DEFAULT_MAX_ENTRIES;
  const now = Date.now();
  const cached = cache.get(url);
  if (cached && now - cached.fetchedAt < ttl) {
    return {
      manifest: cached.manifest,
      etag: cached.etag,
      fromCache: true,
      revalidated: false,
      fetchedAt: cached.fetchedAt
    };
  }
  const headers = { Accept: "application/json" };
  if (cached?.etag) headers["If-None-Match"] = cached.etag;
  const response = await fetchFn(url, { headers });
  if (response.status === 304 && cached) {
    cached.fetchedAt = now;
    cache.set(url, cached);
    return {
      manifest: cached.manifest,
      etag: cached.etag,
      fromCache: true,
      revalidated: true,
      fetchedAt: now
    };
  }
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`fetchManifest: unexpected status ${response.status} for ${url}`);
  }
  const manifest = await response.json();
  const etag = response.headers.get("etag") ?? void 0;
  const entry = { manifest, fetchedAt: now, etag };
  cache.set(url, entry);
  evictIfNeeded(maxEntries);
  return { manifest, etag, fromCache: false, revalidated: false, fetchedAt: now };
}

// src/v3/cert.ts
function isCertValidAt(cert, isoTime) {
  const t = Date.parse(isoTime);
  if (Number.isNaN(t)) {
    return { valid: false, reason: `unparseable timestamp: ${isoTime}` };
  }
  const from = Date.parse(cert.validFrom);
  const until = Date.parse(cert.validUntil);
  if (t < from) {
    return { valid: false, reason: `${isoTime} is before validFrom (${cert.validFrom})` };
  }
  if (t > until) {
    return { valid: false, reason: `${isoTime} is after validUntil (${cert.validUntil})` };
  }
  return { valid: true };
}

// src/v3/sequence-state.ts
var highestSeen = /* @__PURE__ */ new Map();
function clearSequenceState() {
  highestSeen.clear();
}
function checkSequence(domain, sequence) {
  const prior = highestSeen.get(domain) ?? null;
  if (prior !== null && sequence < prior) {
    return { rollback: true, highestSeen: prior, received: sequence };
  }
  return { rollback: false, highestSeen: prior, received: sequence };
}
function recordSequence(domain, sequence) {
  const prior = highestSeen.get(domain);
  if (prior === void 0 || sequence > prior) {
    highestSeen.set(domain, sequence);
  }
}

// src/v3/tsa-trust.ts
var DEFAULT_TRUSTED_TSAS = [];
async function fingerprintCert(certDer) {
  const buf = await crypto.subtle.digest("SHA-256", certDer);
  const bytes = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}
async function isTrustedTsaCert(certDer, trustList = DEFAULT_TRUSTED_TSAS) {
  if (trustList.length === 0) {
    return { trusted: false };
  }
  const fp = await fingerprintCert(certDer);
  const matched = trustList.find((t) => t.certFingerprintSha256.toLowerCase() === fp);
  return { trusted: !!matched, matched };
}

// src/v3/tsa-verify.ts
var SIG_ALG_RSA_SHA256 = "1.2.840.113549.1.1.11";
var SIG_ALG_RSA_SHA512 = "1.2.840.113549.1.1.13";
var SIG_ALG_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
var SIG_ALG_ECDSA_SHA384 = "1.2.840.10045.4.3.3";
function base64ToBytes2(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
function byteArraysEqual2(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
async function importTsaPublicKey(spki, signatureAlgOid) {
  if (signatureAlgOid === SIG_ALG_RSA_SHA256) {
    return {
      key: await crypto.subtle.importKey(
        "spki",
        spki,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"]
      ),
      algorithm: { name: "RSASSA-PKCS1-v1_5" }
    };
  }
  if (signatureAlgOid === SIG_ALG_RSA_SHA512) {
    return {
      key: await crypto.subtle.importKey(
        "spki",
        spki,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
        false,
        ["verify"]
      ),
      algorithm: { name: "RSASSA-PKCS1-v1_5" }
    };
  }
  if (signatureAlgOid === SIG_ALG_ECDSA_SHA256) {
    return {
      key: await crypto.subtle.importKey(
        "spki",
        spki,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"]
      ),
      algorithm: { name: "ECDSA", hash: "SHA-256" }
    };
  }
  if (signatureAlgOid === SIG_ALG_ECDSA_SHA384) {
    return {
      key: await crypto.subtle.importKey(
        "spki",
        spki,
        { name: "ECDSA", namedCurve: "P-384" },
        false,
        ["verify"]
      ),
      algorithm: { name: "ECDSA", hash: "SHA-384" }
    };
  }
  throw new Error(`unsupported TSA signature algorithm: ${signatureAlgOid}`);
}
async function verifyTsaToken(tokenBase64, expectedHash, trustList = DEFAULT_TRUSTED_TSAS) {
  let tokenDer;
  try {
    tokenDer = base64ToBytes2(tokenBase64);
  } catch (e) {
    return { valid: false, reason: `tsaToken is not valid base64: ${String(e)}` };
  }
  let tst;
  try {
    tst = extractTSTInfo(tokenDer);
  } catch (e) {
    return { valid: false, reason: `failed to parse TimeStampToken: ${String(e)}` };
  }
  if (!byteArraysEqual2(tst.messageImprintHash, expectedHash)) {
    return {
      valid: false,
      reason: `TSA token hash does not match envelope hash`
    };
  }
  const trust = await isTrustedTsaCert(tst.tsaCertDer, trustList);
  if (!trust.trusted) {
    if (trustList.length === 0) {
      return {
        valid: false,
        reason: "no TSA trust list configured (default is empty per charter \xA76); pass opts.trustedTsas"
      };
    }
    return {
      valid: false,
      reason: `TSA certificate not in trust list (cert not recognized)`
    };
  }
  let pubKey;
  let algorithm;
  try {
    const spki = extractCertSPKI(tst.tsaCertDer);
    const result = await importTsaPublicKey(spki, tst.signatureAlgOid);
    pubKey = result.key;
    algorithm = result.algorithm;
  } catch (e) {
    return { valid: false, reason: `could not import TSA public key: ${String(e)}` };
  }
  try {
    const ok = await crypto.subtle.verify(
      algorithm,
      pubKey,
      tst.signatureBytes,
      tst.signedAttrsDer
    );
    if (!ok) {
      return {
        valid: false,
        reason: `TSA signature verification failed`
      };
    }
  } catch (e) {
    return { valid: false, reason: `signature verification threw: ${String(e)}` };
  }
  return {
    valid: true,
    genTime: tst.genTime.toISOString(),
    tsaName: trust.matched?.name ?? "trusted TSA",
    reason: `TSA-attested at ${tst.genTime.toISOString()} by ${trust.matched?.name ?? "trusted TSA"}`
  };
}

// src/v3/dane.ts
function parseTxtRecord(data) {
  const stripped = data.replace(/^"|"$/g, "");
  const out = {};
  for (const part of stripped.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    out[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
  }
  return out;
}
async function verifyDane(domain, manifestRootKey, opts = {}) {
  const endpoint = opts.dohEndpoint ?? "https://1.1.1.1/dns-query";
  const fetchFn = opts.fetch ?? globalThis.fetch;
  const timeoutMs = opts.timeoutMs ?? 5e3;
  const url = `${endpoint}?name=_tsp.${encodeURIComponent(domain)}&type=TXT`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  try {
    response = await fetchFn(url, {
      headers: { Accept: "application/dns-json" },
      signal: controller.signal
    });
  } catch (e) {
    clearTimeout(timer);
    return { valid: false, reason: `DoH request failed: ${e.message}` };
  }
  clearTimeout(timer);
  if (!response.ok) {
    return { valid: false, reason: `DoH returned HTTP ${response.status}` };
  }
  let body;
  try {
    body = await response.json();
  } catch (e) {
    return { valid: false, reason: `DoH response not valid JSON: ${e.message}` };
  }
  if (body.Status !== 0) {
    return { valid: false, reason: `DNS query returned status ${body.Status}` };
  }
  if (body.AD !== true) {
    return {
      valid: false,
      reason: `DNSSEC validation flag (AD) is false; DANE requires DNSSEC-signed records`
    };
  }
  if (!body.Answer || body.Answer.length === 0) {
    return { valid: false, reason: `no _tsp TXT record found for ${domain}` };
  }
  for (const ans of body.Answer) {
    if (ans.type !== 16) continue;
    const fields = parseTxtRecord(ans.data);
    if (fields.v !== "tsp1") continue;
    if (!fields.rootKeyHash) continue;
    const expectedHash = await sha256Hex(canonicalize(manifestRootKey));
    const expected = fields.rootKeyHash.replace(/^sha256-/, "").toLowerCase();
    if (expected === expectedHash || isBase64MatchingHex(expected, expectedHash)) {
      return {
        valid: true,
        reason: `DANE TXT record validated; rootKey fingerprint matches`,
        manifestUrlFromDns: fields.manifest
      };
    }
    return {
      valid: false,
      reason: `DANE rootKeyHash (${expected}) does not match manifest rootKey hash (${expectedHash})`
    };
  }
  return { valid: false, reason: `no TXT record with v=tsp1 found` };
}
function isBase64MatchingHex(b64, hex) {
  try {
    const decoded = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    let asHex = "";
    for (const b of decoded) asHex += b.toString(16).padStart(2, "0");
    return asHex === hex;
  } catch {
    return false;
  }
}

// src/v3/verify-online.ts
var PASS2 = (detail) => ({ status: "passed", detail });
var FAIL2 = (detail, evidence) => ({ status: "failed", detail, evidence });
var SKIP2 = (detail) => ({ status: "skipped", detail });
var enc2 = new TextEncoder();
function hexToBytes2(hex) {
  if (hex.length % 2) throw new Error("hex string must be even");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function deriveManifestUrl(keyRef) {
  const hashIdx = keyRef.indexOf("#");
  if (hashIdx === -1) throw new Error(`keyRef missing fragment: ${keyRef}`);
  const url = keyRef.slice(0, hashIdx);
  const instanceId = keyRef.slice(hashIdx + 1);
  const u = new URL(url);
  return { url, instanceId, domain: u.hostname };
}
function base64ToBytes3(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
async function verifyOnline(envelope, opts = {}) {
  const checks = {
    schema: SKIP2("not yet checked"),
    contentHash: SKIP2("not yet checked"),
    ledgerHash: SKIP2("not yet checked"),
    manifestFetch: SKIP2("not yet checked"),
    rootSignature: SKIP2("not yet checked"),
    certChain: SKIP2("not yet checked"),
    certValidity: SKIP2("not yet checked"),
    revocation: SKIP2("not yet checked"),
    tsa: SKIP2("not yet checked"),
    signatures: []
  };
  const warnings = [];
  if (opts.requireDane) {
    checks.dane = SKIP2("DANE check not yet performed");
  }
  if (envelope.tsp !== TSP_V3_VERSION) {
    checks.schema = FAIL2(`expected tsp="${TSP_V3_VERSION}", got "${envelope.tsp}"`);
    return finalize(envelope, checks, warnings);
  }
  if (!envelope.content || !envelope.signatures || envelope.signatures.length === 0) {
    checks.schema = FAIL2("envelope missing required fields");
    return finalize(envelope, checks, warnings);
  }
  checks.schema = PASS2("schema is well-formed");
  const expectedContentHash = await sha256Hex(canonicalize(envelope.content.value));
  checks.contentHash = expectedContentHash === envelope.content.hash ? PASS2("content hash matches canonical(value)") : FAIL2(`content hash mismatch: claimed ${envelope.content.hash}, computed ${expectedContentHash}`);
  const ledgerDomain = {
    tsp: envelope.tsp,
    content: envelope.content,
    declaration: envelope.declaration,
    process: envelope.process,
    alignment: envelope.alignment,
    timestamp: envelope.timestamp,
    signatures: envelope.signatures,
    ledger: { id: envelope.ledger.id, prevHash: envelope.ledger.prevHash }
  };
  const expectedLedgerHash = await sha256Hex(canonicalize(ledgerDomain));
  checks.ledgerHash = expectedLedgerHash === envelope.ledger.hash ? PASS2("ledger hash matches canonical(envelope \u2212 ledger.hash)") : FAIL2(`ledger hash mismatch: claimed ${envelope.ledger.hash}, computed ${expectedLedgerHash}`);
  const sig = envelope.signatures[0];
  let manifestUrl;
  let instanceId;
  let domain;
  try {
    const parsed = deriveManifestUrl(sig.keyRef);
    manifestUrl = parsed.url;
    instanceId = parsed.instanceId;
    domain = parsed.domain;
  } catch (e) {
    checks.manifestFetch = FAIL2(`could not parse keyRef: ${String(e)}`);
    return finalize(envelope, checks, warnings);
  }
  let fetchResult;
  try {
    fetchResult = await fetchManifest(manifestUrl, { fetch: opts.fetch, ttlMs: opts.ttlMs });
  } catch (e) {
    checks.manifestFetch = FAIL2(`fetch failed: ${String(e)}`);
    return finalize(envelope, checks, warnings);
  }
  const manifest = fetchResult.manifest;
  const seqCheck = checkSequence(domain, manifest.sequence);
  if (seqCheck.rollback) {
    checks.manifestFetch = FAIL2(
      `rollback detected: cached sequence ${seqCheck.highestSeen}, received ${seqCheck.received}`
    );
    return finalize(envelope, checks, warnings);
  }
  const issuedAtMs = Date.parse(manifest.issuedAt);
  const ageSeconds = Math.floor((Date.now() - issuedAtMs) / 1e3);
  const maxAge = opts.acceptableManifestAgeOverride ?? manifest.acceptableAge.seconds;
  if (ageSeconds > maxAge) {
    checks.manifestFetch = FAIL2(`manifest is stale: ${ageSeconds}s old, max ${maxAge}s`);
    return finalize(envelope, checks, warnings);
  }
  const cacheDetail = fetchResult.fromCache ? fetchResult.revalidated ? `cached, revalidated via ETag, age: ${ageSeconds}s` : `cached, age: ${ageSeconds}s` : `freshly fetched, manifest age: ${ageSeconds}s`;
  checks.manifestFetch = PASS2(cacheDetail);
  const rootSigOk = await verifyManifestSignature(manifest);
  if (!rootSigOk) {
    checks.rootSignature = FAIL2("manifest rootSignatureOverManifest does not validate");
    return finalize(envelope, checks, warnings);
  }
  checks.rootSignature = PASS2("manifest signature valid");
  recordSequence(domain, manifest.sequence);
  const instance = manifest.instances.find((i) => i.id === instanceId);
  if (!instance) {
    checks.certChain = FAIL2(`instance "${instanceId}" not in manifest`);
    return finalize(envelope, checks, warnings);
  }
  const certOk = await verifyInstanceCert(instance, manifest.rootKey);
  if (!certOk) {
    checks.certChain = FAIL2(`instance cert "${instanceId}" rootSignature does not validate`);
    return finalize(envelope, checks, warnings);
  }
  checks.certChain = PASS2(`instance cert "${instanceId}" signed by org-root`);
  const validityResult = isCertValidAt(instance, envelope.timestamp.claimed);
  checks.certValidity = validityResult.valid ? PASS2(`envelope timestamp within cert validity window`) : FAIL2(validityResult.reason ?? "cert not valid at envelope timestamp");
  const revResult = checkRevocation(instanceId, envelope.timestamp.claimed, manifest.revoked);
  if (revResult.status === "not-revoked" || revResult.status === "predates-revocation") {
    checks.revocation = PASS2(revResult.detail);
  } else {
    checks.revocation = FAIL2(revResult.detail);
  }
  if (envelope.timestamp.tsaToken === TSA_PLACEHOLDER_TOKEN) {
    if (opts.acceptLegacyTsa) {
      checks.tsa = SKIP2("legacy alpha placeholder token, accepted via acceptLegacyTsa");
      warnings.push("envelope has legacy placeholder tsaToken; no real TSA attestation");
    } else {
      checks.tsa = FAIL2("legacy placeholder tsaToken; pass acceptLegacyTsa: true to allow");
    }
  } else {
    const tsaInputDomain = {
      tsp: envelope.tsp,
      content: envelope.content,
      declaration: envelope.declaration,
      process: envelope.process,
      alignment: envelope.alignment,
      timestamp: { claimed: envelope.timestamp.claimed, tsaUrl: envelope.timestamp.tsaUrl },
      ledger: { id: envelope.ledger.id, prevHash: envelope.ledger.prevHash },
      signatures: envelope.signatures
    };
    const expectedTsaHash = hexToBytes2(await sha256Hex(canonicalize(tsaInputDomain)));
    const tsaResult = await verifyTsaToken(envelope.timestamp.tsaToken, expectedTsaHash, opts.trustedTsas);
    checks.tsa = tsaResult.valid ? PASS2(tsaResult.reason) : FAIL2(tsaResult.reason);
  }
  if (opts.requireDane) {
    const daneResult = await verifyDane(domain, manifest.rootKey, opts.daneOptions);
    checks.dane = daneResult.valid ? PASS2(daneResult.reason) : FAIL2(daneResult.reason);
  }
  for (const s of envelope.signatures) {
    if (s.algorithm !== "ed25519") {
      checks.signatures.push(FAIL2(`unsupported algorithm: ${s.algorithm}`));
      continue;
    }
    const sigDomain = {
      tsp: envelope.tsp,
      content: envelope.content,
      declaration: envelope.declaration,
      process: envelope.process,
      alignment: envelope.alignment,
      timestamp: { claimed: envelope.timestamp.claimed, tsaUrl: envelope.timestamp.tsaUrl },
      ledger: { id: envelope.ledger.id, prevHash: envelope.ledger.prevHash }
    };
    let pubKey;
    try {
      pubKey = await importPublicKeyJwk(instance.publicKey);
    } catch (e) {
      checks.signatures.push(FAIL2(`could not import instance public key: ${String(e)}`));
      continue;
    }
    let sigBytes;
    try {
      sigBytes = base64ToBytes3(s.signature);
    } catch (e) {
      checks.signatures.push(FAIL2(`signature is not valid base64: ${String(e)}`));
      continue;
    }
    const ok = await verify(pubKey, sigBytes, enc2.encode(canonicalize(sigDomain)));
    checks.signatures.push(
      ok ? PASS2(`signature valid (role=${s.role})`) : FAIL2(`signature invalid (role=${s.role})`)
    );
  }
  return finalize(envelope, checks, warnings);
}
function finalize(envelope, checks, warnings) {
  const mustPass = [
    checks.schema,
    checks.contentHash,
    checks.ledgerHash,
    checks.manifestFetch,
    checks.rootSignature,
    checks.certChain,
    checks.certValidity,
    checks.revocation,
    ...checks.signatures
  ];
  const tsaOk = checks.tsa.status === "passed" || checks.tsa.status === "skipped";
  const daneOk = checks.dane === void 0 || checks.dane.status === "passed";
  const valid = mustPass.every((c) => c.status === "passed") && tsaOk && daneOk;
  return { valid, envelope, checks, warnings };
}

export {
  TSP_V3_VERSION,
  sha256Hex,
  sha256Bytes,
  buildTimeStampReq,
  stampHash,
  TSA_PLACEHOLDER_TOKEN,
  TSA_PLACEHOLDER_URL,
  wrap,
  verifyLocal,
  verifyManifestSignature,
  verifyInstanceCert,
  clearManifestCache,
  fetchManifest,
  isCertValidAt,
  clearSequenceState,
  checkSequence,
  recordSequence,
  DEFAULT_TRUSTED_TSAS,
  fingerprintCert,
  isTrustedTsaCert,
  verifyTsaToken,
  verifyDane,
  verifyOnline
};
