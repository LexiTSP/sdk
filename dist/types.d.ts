/**
 * @lexitsp/sdk · types
 *
 * Core type definitions for Trust Standard Protocol v2.0.
 * Source of truth — duplicated in spec at truststandardprotocol.org/spec.
 */
type ConfidenceLevel = "high" | "medium" | "low" | "critical";
type SourceType = "legal-database" | "government-website" | "official-document" | "academic-paper" | "verified-website" | "model-knowledge" | "user-input" | "unknown";
type Domain = "legal" | "medical" | "welfare" | "tax" | "hr" | "finance" | "education" | "safety" | "general";
/**
 * A citation references the source material a response is based on.
 * The shape is intentionally permissive — implementations can use
 * `text`, `paragraph`, or `quote` depending on domain conventions
 * (legal vs. academic vs. clinical, etc.). At least one identifying
 * field should be present.
 */
interface Citation {
    text?: string;
    paragraph?: string;
    quote?: string;
    url?: string;
    ref?: string;
}
interface Source {
    name: string;
    type: SourceType;
    confidence: number;
    url?: string;
    accessedAt?: string;
    citations?: Citation[];
}
interface Process {
    model: string;
    pipeline: string;
    steps?: string[];
    parameters?: Record<string, unknown>;
    timestamp?: string;
    durationMs?: number;
    tokensIn?: number;
    tokensOut?: number;
}
interface Alignment {
    riskLevel: 0 | 1 | 2 | 3 | 4 | 5;
    ethicsCheck: boolean;
    biasScore: number;
    flags?: string[];
    humanReviewRequired?: boolean;
    domain?: Domain | string;
}
interface LedgerEntry {
    id: string;
    hash: string;
    timestamp: string;
    previousHash?: string;
    blockHeight?: number;
}
interface TrustConfig {
    source: Source;
    process: Process;
    alignment: Alignment;
}
interface TrustEnvelope {
    version: string;
    content: string;
    confidenceScore: number;
    confidenceLevel: ConfidenceLevel;
    source: Source;
    process: Process;
    alignment: Alignment;
    ledger: LedgerEntry;
}
interface VerificationResult {
    valid: boolean;
    hashValid: boolean;
    scoreValid: boolean;
    errors: string[];
}
interface ChainVerificationResult {
    valid: boolean;
    totalEnvelopes: number;
    brokenAt?: number;
    reason?: string;
    errors: string[];
}
interface TrustStats {
    totalInteractions: number;
    averageConfidence: number;
    confidenceLevelCounts: Record<ConfidenceLevel, number>;
    riskLevelCounts: Record<string, number>;
    topSources: Array<{
        name: string;
        count: number;
    }>;
    topModels: Array<{
        model: string;
        count: number;
    }>;
    lastHash?: string;
}

export type { Alignment, ChainVerificationResult, Citation, ConfidenceLevel, Domain, LedgerEntry, Process, Source, SourceType, TrustConfig, TrustEnvelope, TrustStats, VerificationResult };
