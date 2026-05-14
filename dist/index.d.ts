import { TrustEnvelope, TrustConfig, VerificationResult, ChainVerificationResult, SourceType, ConfidenceLevel, Source, Process, Alignment } from './types.js';
export { Citation, Domain, LedgerEntry, TrustStats } from './types.js';

/**
 * @lexitsp/sdk · envelope
 *
 * Trust Envelope construction. The primary export of the SDK.
 *
 * Usage:
 *   const envelope = await wrap(content, config, { previousHash });
 */

declare const TSP_VERSION = "2.0.0";
interface WrapOptions {
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
declare function wrap(content: string, config: TrustConfig, options?: WrapOptions): Promise<TrustEnvelope>;
/**
 * Convert a TrustEnvelope to JSON-LD form for cross-system interop.
 */
declare function toJsonLd(envelope: TrustEnvelope): Record<string, unknown>;

/**
 * @lexitsp/sdk · verify
 *
 * Single-envelope and chain-wide verification.
 *
 * verify(env)        — checks one envelope's hash and score
 * verifyChain(envs)  — checks the full hash chain
 */

/**
 * Verify a single TrustEnvelope.
 *
 * Recomputes the hash from the envelope's contents and compares to
 * the recorded hash. Recomputes the confidenceScore and compares too.
 */
declare function verify(envelope: TrustEnvelope): Promise<VerificationResult>;
/**
 * Verify an entire chain of envelopes.
 *
 * Walks the array in order, verifying:
 *   1. Each envelope's hash and score (verify() above)
 *   2. Each envelope.ledger.previousHash matches the previous envelope's hash
 *
 * Returns the index of the first broken envelope, or { valid: true } if intact.
 */
declare function verifyChain(envelopes: TrustEnvelope[]): Promise<ChainVerificationResult>;

/**
 * @lexitsp/sdk · scoring
 *
 * Deterministic confidence-score computation per TSP spec v2.0.
 *
 * Score = scoreSource × 0.5 + scoreProcess × 0.3 + scoreAlignment × 0.2
 *
 * Every implementation produces the same score for the same inputs.
 * This reproducibility is what makes the score auditable.
 */

declare const WEIGHTS: {
    readonly source: 0.5;
    readonly process: 0.3;
    readonly alignment: 0.2;
};
declare const SOURCE_TYPE_SCORES: Record<SourceType, number>;
declare function scoreSource(s: Source): number;
declare function scoreProcess(p: Process): number;
declare function scoreAlignment(a: Alignment): number;
declare function computeConfidenceScore(s: Source, p: Process, a: Alignment): number;
declare function classifyLevel(score: number): ConfidenceLevel;

/**
 * @lexitsp/sdk · crypto
 *
 * SHA-256 hashing and canonical JSON serialization (RFC 8785-style).
 * Uses Web Crypto API — works in Node 18+, Bun, browsers, and edge runtimes.
 */
/**
 * Compute SHA-256 hex digest of a string input.
 */
declare function sha256(input: string): Promise<string>;
/**
 * Canonical JSON serialization — deterministic across implementations.
 *
 * Rules:
 * - Object keys sorted alphabetically
 * - Arrays preserve order
 * - No insignificant whitespace
 * - Standard JSON escaping for strings and numbers (delegated to JSON.stringify)
 *
 * This guarantees that the same envelope produces the same hash regardless
 * of language, platform, or implementation. Compatible with RFC 8785 (JCS).
 */
declare function canonicalJson(value: unknown): string;

/**
 * @lexitsp/sdk
 *
 * Trust Standard Protocol — runtime compliance layer for the EU AI Act.
 * Wraps AI responses in cryptographically verifiable Trust Envelopes.
 *
 * Quickstart:
 *
 *   import { tsp } from "@lexitsp/sdk";
 *
 *   const envelope = await tsp.wrap("Du har rett på AAP fordi...", {
 *     source: { name: "Lovdata", type: "legal-database", confidence: 0.95 },
 *     process: { model: "gpt-4o", pipeline: "RAG + Legal" },
 *     alignment: { riskLevel: 1, ethicsCheck: true, biasScore: 0.05 },
 *   });
 *
 *   const result = await tsp.verify(envelope);
 *   //  { valid: true, hashValid: true, scoreValid: true, errors: [] }
 */

declare const tsp: {
    version: string;
    wrap: typeof wrap;
    verify: typeof verify;
    verifyChain: typeof verifyChain;
    toJsonLd: typeof toJsonLd;
};

export { Alignment, ChainVerificationResult, ConfidenceLevel, Process, SOURCE_TYPE_SCORES, Source, SourceType, TSP_VERSION, TrustConfig, TrustEnvelope, VerificationResult, WEIGHTS, type WrapOptions, canonicalJson, classifyLevel, computeConfidenceScore, scoreAlignment, scoreProcess, scoreSource, sha256, toJsonLd, tsp, verify, verifyChain, wrap };
