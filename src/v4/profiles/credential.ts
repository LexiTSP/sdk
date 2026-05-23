/**
 * @lexitsp/sdk v4 · profiles/credential — EXPERIMENTAL
 *
 * Helper for building `provenance: CredentialProvenance`. Intended for
 * diplomas, course completions, professional certifications, and other
 * "X was achieved by Y at time T" claims.
 *
 * Note: criteria are referenced by stable id (think OpenBadges criteria
 * URL or an institutional course code), not embedded as free text. This
 * is deliberate — Charter §11 (data minimization) applies to credentials.
 */

import type {
  CredentialCriteria,
  CredentialIssuer,
  CredentialProvenance,
  ISO8601,
} from "../types";

export interface CredentialProfileInput {
  issuer: CredentialIssuer;
  criteria: CredentialCriteria;
  achievedAt: ISO8601;
  validUntil?: ISO8601;
}

export function credentialProfile(
  input: CredentialProfileInput,
): CredentialProvenance {
  return {
    kind: "credential",
    issuer: input.issuer,
    criteria: input.criteria,
    achievedAt: input.achievedAt,
    ...(input.validUntil !== undefined ? { validUntil: input.validUntil } : {}),
  };
}
