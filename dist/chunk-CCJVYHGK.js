// src/v3/canonical.ts
var REQUIRES_ESCAPE = /[\x00-\x1f"\\]/g;
var ESCAPE_MAP = {
  "\b": "\\b",
  "	": "\\t",
  "\n": "\\n",
  "\f": "\\f",
  "\r": "\\r",
  '"': '\\"',
  "\\": "\\\\"
};
function escapeChar(c) {
  if (c in ESCAPE_MAP) return ESCAPE_MAP[c];
  const code = c.charCodeAt(0);
  return "\\u" + code.toString(16).padStart(4, "0");
}
function canonicalString(s) {
  return '"' + s.replace(REQUIRES_ESCAPE, escapeChar) + '"';
}
function canonicalNumber(n) {
  if (!Number.isFinite(n)) {
    throw new Error(`canonicalize: non-finite number not allowed: ${n}`);
  }
  if (Object.is(n, -0)) return "0";
  return JSON.stringify(n);
}
function canonicalize(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return canonicalNumber(value);
  if (typeof value === "string") return canonicalString(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value;
    const keys = Object.keys(obj).sort((a, b) => {
      if (a < b) return -1;
      if (a > b) return 1;
      return 0;
    });
    return "{" + keys.map((k) => canonicalString(k) + ":" + canonicalize(obj[k])).join(",") + "}";
  }
  throw new Error(`canonicalize: unsupported value type: ${typeof value}`);
}

// src/v3/crypto.ts
var ED25519_ALGORITHM = { name: "Ed25519" };
async function generateKeyPair() {
  const kp = await crypto.subtle.generateKey(
    ED25519_ALGORITHM,
    true,
    ["sign", "verify"]
  );
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}
async function sign(privateKey, data) {
  const buf = await crypto.subtle.sign(ED25519_ALGORITHM, privateKey, data);
  return new Uint8Array(buf);
}
async function verify(publicKey, signature, data) {
  return crypto.subtle.verify(ED25519_ALGORITHM, publicKey, signature, data);
}
async function exportPublicKeyJwk(publicKey) {
  const jwk = await crypto.subtle.exportKey("jwk", publicKey);
  return jwk;
}
async function importPublicKeyJwk(jwk) {
  return crypto.subtle.importKey("jwk", jwk, ED25519_ALGORITHM, true, ["verify"]);
}
async function importPrivateKeyJwk(jwk) {
  return crypto.subtle.importKey("jwk", jwk, ED25519_ALGORITHM, true, ["sign"]);
}
async function exportPrivateKeyJwk(privateKey) {
  return crypto.subtle.exportKey("jwk", privateKey);
}

// src/v3/manifest-sign.ts
var enc = new TextEncoder();
function bytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
async function signInstanceCert(input) {
  const sigBytes = await input.rootSigner.sign(
    enc.encode(canonicalize(input.payload))
  );
  return {
    ...input.payload,
    rootSignature: bytesToBase64(sigBytes)
  };
}
async function signManifest(input) {
  const unsigned = {
    tsp: "3.0",
    organization: input.organization,
    rootKey: input.rootSigner.publicKey,
    instances: input.instances,
    revoked: input.revoked,
    sequence: input.sequence,
    issuedAt: input.issuedAt,
    acceptableAge: input.acceptableAge
  };
  const sigBytes = await input.rootSigner.sign(enc.encode(canonicalize(unsigned)));
  return {
    ...unsigned,
    rootSignatureOverManifest: bytesToBase64(sigBytes)
  };
}

// src/v3/revocation.ts
function checkRevocation(instanceId, envelopeTime, revoked) {
  const entry = revoked.find((r) => r.id === instanceId);
  if (!entry) {
    return { status: "not-revoked", detail: `instance ${instanceId} not in revocation list` };
  }
  const envT = Date.parse(envelopeTime);
  const revT = Date.parse(entry.revokedAt);
  if (Number.isNaN(envT) || Number.isNaN(revT)) {
    return {
      status: "revoked",
      detail: `instance ${instanceId} revoked but timestamps unparseable; conservative reject`
    };
  }
  if (envT < revT) {
    return {
      status: "predates-revocation",
      detail: `instance ${instanceId} revoked at ${entry.revokedAt} (reason: ${entry.reason}), envelope predates revocation`
    };
  }
  return {
    status: "revoked",
    detail: `instance ${instanceId} revoked at ${entry.revokedAt} (reason: ${entry.reason})`
  };
}
function pruneRevoked(revoked, opts) {
  const nowMs = Date.parse(opts.now);
  const graceMs = opts.graceDays * 24 * 60 * 60 * 1e3;
  const acceptableMs = opts.acceptableAgeSeconds * 1e3;
  return revoked.filter((entry) => {
    const revMs = Date.parse(entry.revokedAt);
    if (Number.isNaN(revMs)) return true;
    const cutoff = revMs + acceptableMs + graceMs;
    return cutoff >= nowMs;
  });
}

export {
  canonicalize,
  generateKeyPair,
  sign,
  verify,
  exportPublicKeyJwk,
  importPublicKeyJwk,
  importPrivateKeyJwk,
  exportPrivateKeyJwk,
  signInstanceCert,
  signManifest,
  checkRevocation,
  pruneRevoked
};
