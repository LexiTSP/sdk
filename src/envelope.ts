/**
 * @lexitsp/sdk · envelope
 *
 * Trust Envelope construction. The primary export of the SDK.
 *
 * Usage:
 *   const envelope = await wrap(content, config, { previousHash });
 */

import { nanoid } from "nanoid";
import { canonicalJson, sha256 } from "./crypto";
import { classifyLevel, computeConfidenceScore } from "./scoring";
import type {
  LedgerEntry,
  TrustConfig,
  TrustEnvelope,
} from "./types";

export const TSP_VERSION = "2.0.0";

export interface WrapOptions {
  previousHash?: string;
  blockHeight?: number;
  /** Override the timestamp (testing only). */
  timestamp?: string;
  /** Override the envelope id (testing only). */
  id?: string;
}

/**
 * Wrap content in a TrustEnvelope.
 *
 * Computes confidenceScore deterministically from the config,
 * generates a stable id, hashes the canonical representation,
 * and links to the previous hash if provided.
 */
export async function wrap(
  content: string,
  config: TrustConfig,
  options: WrapOptions = {},
): Promise<TrustEnvelope> {
  const now = options.timestamp ?? new Date().toISOString();
  const source = {
    ...config.source,
    accessedAt: config.source.accessedAt ?? now,
  };
  const process = {
    ...config.process,
    timestamp: config.process.timestamp ?? now,
  };
  const alignment = config.alignment;

  const confidenceScore = computeConfidenceScore(source, process, alignment);
  const confidenceLevel = classifyLevel(confidenceScore);

  const id = options.id ?? `tsp_${nanoid(16)}`;

  const hashable = canonicalJson({
    version: TSP_VERSION,
    id,
    content,
    source,
    process,
    alignment,
    previousHash: options.previousHash ?? null,
  });
  const hash = await sha256(hashable);

  const ledger: LedgerEntry = {
    id,
    hash,
    timestamp: now,
    previousHash: options.previousHash,
    blockHeight: options.blockHeight,
  };

  return {
    version: TSP_VERSION,
    content,
    confidenceScore,
    confidenceLevel,
    source,
    process,
    alignment,
    ledger,
  };
}

/**
 * Convert a TrustEnvelope to JSON-LD form for cross-system interop.
 */
export function toJsonLd(envelope: TrustEnvelope): Record<string, unknown> {
  return {
    "@context": "https://truststandardprotocol.com/context/v2",
    "@type": "TrustEnvelope",
    "@id": envelope.ledger.id,
    version: envelope.version,
    content: envelope.content,
    confidence: {
      score: envelope.confidenceScore,
      level: envelope.confidenceLevel,
    },
    source: envelope.source,
    process: envelope.process,
    alignment: envelope.alignment,
    ledger: envelope.ledger,
  };
}
