/**
 * @lexitsp/sdk v4 · profiles/attestation — EXPERIMENTAL
 *
 * Helper for building `provenance: AttestationProvenance`. A general
 * "I claim X happened" envelope for cases that don't fit AI, credential,
 * or supply-chain. If a domain emerges with enough volume, it gets its
 * own `kind` via a follow-up RFC rather than overloading this one.
 */

import type {
  AttestationActor,
  AttestationBasis,
  AttestationClaim,
  AttestationProvenance,
} from "../types";

export interface AttestationProfileInput {
  attester: AttestationActor;
  claim: AttestationClaim;
  basis: AttestationBasis;
}

export function attestationProfile(
  input: AttestationProfileInput,
): AttestationProvenance {
  return {
    kind: "attestation",
    attester: input.attester,
    claim: input.claim,
    basis: input.basis,
  };
}
