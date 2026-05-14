/**
 * @lexitsp/sdk · types
 *
 * Core type definitions for Trust Standard Protocol v2.0.
 * Source of truth — duplicated in spec at truststandardprotocol.org/spec.
 */

export type ConfidenceLevel = "high" | "medium" | "low" | "critical";

export type SourceType =
  | "legal-database"
  | "government-website"
  | "official-document"
  | "academic-paper"
  | "verified-website"
  | "model-knowledge"
  | "user-input"
  | "unknown";

export type Domain =
  | "legal"
  | "medical"
  | "welfare"
  | "tax"
  | "hr"
  | "finance"
  | "education"
  | "safety"
  | "general";

/**
 * A citation references the source material a response is based on.
 * The shape is intentionally permissive — implementations can use
 * `text`, `paragraph`, or `quote` depending on domain conventions
 * (legal vs. academic vs. clinical, etc.). At least one identifying
 * field should be present.
 */
export interface Citation {
  text?: string;
  paragraph?: string;
  quote?: string;
  url?: string;
  ref?: string;
}

export interface Source {
  name: string;
  type: SourceType;
  confidence: number; // 0-1
  url?: string;
  accessedAt?: string; // ISO 8601
  citations?: Citation[];
}

export interface Process {
  model: string;
  pipeline: string;
  steps?: string[];
  parameters?: Record<string, unknown>;
  timestamp?: string;
  durationMs?: number;
  tokensIn?: number;
  tokensOut?: number;
}

export interface Alignment {
  riskLevel: 0 | 1 | 2 | 3 | 4 | 5;
  ethicsCheck: boolean;
  biasScore: number; // 0-1, lower is better
  flags?: string[];
  humanReviewRequired?: boolean;
  domain?: Domain | string; // string fallback for domain extensions
}

export interface LedgerEntry {
  id: string;
  hash: string;
  timestamp: string;
  previousHash?: string;
  blockHeight?: number;
}

export interface TrustConfig {
  source: Source;
  process: Process;
  alignment: Alignment;
}

export interface TrustEnvelope {
  version: string;
  content: string;
  confidenceScore: number; // 0-100
  confidenceLevel: ConfidenceLevel;
  source: Source;
  process: Process;
  alignment: Alignment;
  ledger: LedgerEntry;
}

export interface VerificationResult {
  valid: boolean;
  hashValid: boolean;
  scoreValid: boolean;
  errors: string[];
}

export interface ChainVerificationResult {
  valid: boolean;
  totalEnvelopes: number;
  brokenAt?: number;
  reason?: string;
  errors: string[];
}

export interface TrustStats {
  totalInteractions: number;
  averageConfidence: number;
  confidenceLevelCounts: Record<ConfidenceLevel, number>;
  riskLevelCounts: Record<string, number>;
  topSources: Array<{ name: string; count: number }>;
  topModels: Array<{ model: string; count: number }>;
  lastHash?: string;
}
