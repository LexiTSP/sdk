/**
 * @lexitsp/sdk v3 · cert validity
 */

import type { InstanceCertEntry } from "./manifest-types";

export interface CertValidityResult {
  valid: boolean;
  reason?: string;
}

export function isCertValidAt(
  cert: InstanceCertEntry,
  isoTime: string
): CertValidityResult {
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
