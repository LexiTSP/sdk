/**
 * @lexitsp/sdk · verify
 *
 * Single-envelope and chain-wide verification.
 *
 * verify(env)        — checks one envelope's hash and score
 * verifyChain(envs)  — checks the full hash chain
 */

import { canonicalJson, sha256 } from "./crypto";
import { computeConfidenceScore } from "./scoring";
import type {
  ChainVerificationResult,
  TrustEnvelope,
  VerificationResult,
} from "./types";

/**
 * Verify a single TrustEnvelope.
 *
 * Recomputes the hash from the envelope's contents and compares to
 * the recorded hash. Recomputes the confidenceScore and compares too.
 */
export async function verify(
  envelope: TrustEnvelope,
): Promise<VerificationResult> {
  const errors: string[] = [];

  const hashable = canonicalJson({
    version: envelope.version,
    id: envelope.ledger.id,
    content: envelope.content,
    source: envelope.source,
    process: envelope.process,
    alignment: envelope.alignment,
    previousHash: envelope.ledger.previousHash ?? null,
  });
  const expectedHash = await sha256(hashable);
  const hashValid = expectedHash === envelope.ledger.hash;
  if (!hashValid) {
    errors.push(
      `Hash mismatch: expected ${expectedHash.slice(0, 12)}..., got ${envelope.ledger.hash.slice(0, 12)}...`,
    );
  }

  const expectedScore = computeConfidenceScore(
    envelope.source,
    envelope.process,
    envelope.alignment,
  );
  const scoreValid = expectedScore === envelope.confidenceScore;
  if (!scoreValid) {
    errors.push(
      `Score mismatch: expected ${expectedScore}, got ${envelope.confidenceScore}`,
    );
  }

  return {
    valid: hashValid && scoreValid,
    hashValid,
    scoreValid,
    errors,
  };
}

/**
 * Verify an entire chain of envelopes.
 *
 * Walks the array in order, verifying:
 *   1. Each envelope's hash and score (verify() above)
 *   2. Each envelope.ledger.previousHash matches the previous envelope's hash
 *
 * Returns the index of the first broken envelope, or { valid: true } if intact.
 */
export async function verifyChain(
  envelopes: TrustEnvelope[],
): Promise<ChainVerificationResult> {
  const errors: string[] = [];

  for (let i = 0; i < envelopes.length; i++) {
    const e = envelopes[i];
    const single = await verify(e);

    if (!single.valid) {
      return {
        valid: false,
        totalEnvelopes: envelopes.length,
        brokenAt: i,
        reason: single.errors[0] ?? "envelope invalid",
        errors: single.errors,
      };
    }

    if (i > 0) {
      const prev = envelopes[i - 1];
      if (e.ledger.previousHash !== prev.ledger.hash) {
        const reason = `chain link broken at index ${i}: previousHash ${
          e.ledger.previousHash?.slice(0, 12) ?? "(none)"
        }... does not match prior hash ${prev.ledger.hash.slice(0, 12)}...`;
        errors.push(reason);
        return {
          valid: false,
          totalEnvelopes: envelopes.length,
          brokenAt: i,
          reason,
          errors,
        };
      }
    }
  }

  return {
    valid: true,
    totalEnvelopes: envelopes.length,
    errors: [],
  };
}
