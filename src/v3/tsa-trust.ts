/**
 * @lexitsp/sdk v3 · TSA trust list
 *
 * Per spec decision Q3.4/B: explicit cert-fingerprint whitelist.
 *
 * The SDK ships with EMPTY default trust list. Operators must explicitly
 * configure trusted TSAs via verifyOnline(env, { trustedTsas: [...] }) or
 * by passing a custom list. This is charter §6 honest:  we don't claim
 * trust we haven't earned via inspection.
 *
 * To obtain a fingerprint for a TSA cert:
 *   openssl x509 -in tsa.crt -fingerprint -sha256 -noout
 * Strip the colons and lowercase the result.
 *
 * For development, use addTrustedTsa() at process startup or pass via opts.
 */

import { sha256Hex } from "./canonical-hash";

export interface TrustedTsa {
  /** Human-readable name, e.g. "Buypass TSA". Used in verify-result messages. */
  name: string;
  /** SHA-256 hex digest of the TSA's cert (DER), lowercase, no separators. */
  certFingerprintSha256: string;
  /** Optional notes (eIDAS-qualified? prod-vs-dev? etc.) */
  notes?: string;
}

/**
 * SDK default is intentionally empty per charter §6. Operators must
 * configure their trust posture explicitly.
 */
export const DEFAULT_TRUSTED_TSAS: TrustedTsa[] = [];

/**
 * Compute the SHA-256 fingerprint of a TSA cert (DER bytes).
 * Returns lowercase hex with no separators.
 */
export async function fingerprintCert(certDer: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", certDer as unknown as BufferSource);
  const bytes = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

export async function isTrustedTsaCert(
  certDer: Uint8Array,
  trustList: TrustedTsa[] = DEFAULT_TRUSTED_TSAS
): Promise<{ trusted: boolean; matched?: TrustedTsa }> {
  if (trustList.length === 0) {
    return { trusted: false };
  }
  const fp = await fingerprintCert(certDer);
  const matched = trustList.find((t) => t.certFingerprintSha256.toLowerCase() === fp);
  return { trusted: !!matched, matched };
}
