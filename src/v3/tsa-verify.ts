/**
 * @lexitsp/sdk v3 · TSA token verification
 *
 * Verifies an RFC 3161 TimeStampToken:
 *   1. Parse token, extract TSTInfo + TSA cert + signature
 *   2. Verify messageImprint hash matches expected
 *   3. Verify TSA cert fingerprint is in trust list
 *   4. Import cert SPKI as Web Crypto key, verify signature over signedAttrs
 */

import { extractTSTInfo, extractCertSPKI } from "./asn1";
import { isTrustedTsaCert, type TrustedTsa, DEFAULT_TRUSTED_TSAS } from "./tsa-trust";

// Common signature algorithm OIDs we support
const SIG_ALG_RSA_SHA256 = "1.2.840.113549.1.1.11";
const SIG_ALG_RSA_SHA512 = "1.2.840.113549.1.1.13";
const SIG_ALG_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
const SIG_ALG_ECDSA_SHA384 = "1.2.840.10045.4.3.3";

export interface VerifyTsaResult {
  valid: boolean;
  genTime?: string;
  tsaName?: string;
  reason: string;
}

function base64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function byteArraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function importTsaPublicKey(
  spki: Uint8Array,
  signatureAlgOid: string
): Promise<{ key: CryptoKey; algorithm: AlgorithmIdentifier }> {
  if (signatureAlgOid === SIG_ALG_RSA_SHA256) {
    return {
      key: await crypto.subtle.importKey(
        "spki",
        spki as unknown as BufferSource,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"]
      ),
      algorithm: { name: "RSASSA-PKCS1-v1_5" },
    };
  }
  if (signatureAlgOid === SIG_ALG_RSA_SHA512) {
    return {
      key: await crypto.subtle.importKey(
        "spki",
        spki as unknown as BufferSource,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
        false,
        ["verify"]
      ),
      algorithm: { name: "RSASSA-PKCS1-v1_5" },
    };
  }
  if (signatureAlgOid === SIG_ALG_ECDSA_SHA256) {
    return {
      key: await crypto.subtle.importKey(
        "spki",
        spki as unknown as BufferSource,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"]
      ),
      algorithm: { name: "ECDSA", hash: "SHA-256" } as EcdsaParams,
    };
  }
  if (signatureAlgOid === SIG_ALG_ECDSA_SHA384) {
    return {
      key: await crypto.subtle.importKey(
        "spki",
        spki as unknown as BufferSource,
        { name: "ECDSA", namedCurve: "P-384" },
        false,
        ["verify"]
      ),
      algorithm: { name: "ECDSA", hash: "SHA-384" } as EcdsaParams,
    };
  }
  throw new Error(`unsupported TSA signature algorithm: ${signatureAlgOid}`);
}

export async function verifyTsaToken(
  tokenBase64: string,
  expectedHash: Uint8Array,
  trustList: TrustedTsa[] = DEFAULT_TRUSTED_TSAS
): Promise<VerifyTsaResult> {
  let tokenDer: Uint8Array;
  try {
    tokenDer = base64ToBytes(tokenBase64);
  } catch (e) {
    return { valid: false, reason: `tsaToken is not valid base64: ${String(e)}` };
  }

  let tst;
  try {
    tst = extractTSTInfo(tokenDer);
  } catch (e) {
    return { valid: false, reason: `failed to parse TimeStampToken: ${String(e)}` };
  }

  if (!byteArraysEqual(tst.messageImprintHash, expectedHash)) {
    return {
      valid: false,
      reason: `TSA token hash does not match envelope hash`,
    };
  }

  const trust = await isTrustedTsaCert(tst.tsaCertDer, trustList);
  if (!trust.trusted) {
    if (trustList.length === 0) {
      return {
        valid: false,
        reason: "no TSA trust list configured (default is empty per charter §6); pass opts.trustedTsas",
      };
    }
    return {
      valid: false,
      reason: `TSA certificate not in trust list (cert not recognized)`,
    };
  }

  // Verify signature on signedAttrs
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
      tst.signatureBytes as unknown as BufferSource,
      tst.signedAttrsDer as unknown as BufferSource
    );
    if (!ok) {
      return {
        valid: false,
        reason: `TSA signature verification failed`,
      };
    }
  } catch (e) {
    return { valid: false, reason: `signature verification threw: ${String(e)}` };
  }

  return {
    valid: true,
    genTime: tst.genTime.toISOString(),
    tsaName: trust.matched?.name ?? "trusted TSA",
    reason: `TSA-attested at ${tst.genTime.toISOString()} by ${trust.matched?.name ?? "trusted TSA"}`,
  };
}
