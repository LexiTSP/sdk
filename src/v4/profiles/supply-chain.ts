/**
 * @lexitsp/sdk v4 · profiles/supply-chain — EXPERIMENTAL
 *
 * Helper for building `provenance: SupplyChainProvenance`. Origin plus
 * an ordered chain of transformations.
 *
 * The `transformations[].inputs[]` field references upstream TSP
 * envelopes by `ledger.id`. Verifiers MUST NOT follow those references
 * during verification of the referencing envelope — reference
 * resolution is a separate opt-in operation. This prevents amplification
 * attacks and recursive-verification storms (see RFC 0001 §
 * "Security and Privacy Impact").
 */

import type {
  SupplyChainOrigin,
  SupplyChainProvenance,
  SupplyChainTransformation,
} from "../types";

export interface SupplyChainProfileInput {
  origin: SupplyChainOrigin;
  transformations: SupplyChainTransformation[];
}

export function supplyChainProfile(
  input: SupplyChainProfileInput,
): SupplyChainProvenance {
  return {
    kind: "supply-chain",
    origin: input.origin,
    transformations: input.transformations,
  };
}
