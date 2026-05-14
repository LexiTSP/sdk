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

export { TSP_VERSION, wrap, toJsonLd } from "./envelope";
export type { WrapOptions } from "./envelope";

export { verify, verifyChain } from "./verify";

export {
  computeConfidenceScore,
  classifyLevel,
  scoreSource,
  scoreProcess,
  scoreAlignment,
  WEIGHTS,
  SOURCE_TYPE_SCORES,
} from "./scoring";

export { sha256, canonicalJson } from "./crypto";

export type {
  Alignment,
  ChainVerificationResult,
  Citation,
  ConfidenceLevel,
  Domain,
  LedgerEntry,
  Process,
  Source,
  SourceType,
  TrustConfig,
  TrustEnvelope,
  TrustStats,
  VerificationResult,
} from "./types";

// Convenience namespace for less-typed import sites
import { wrap, toJsonLd, TSP_VERSION } from "./envelope";
import { verify, verifyChain } from "./verify";

export const tsp = {
  version: TSP_VERSION,
  wrap,
  verify,
  verifyChain,
  toJsonLd,
};
