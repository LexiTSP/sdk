/**
 * @lexitsp/sdk v3 · types
 *
 * Trust Standard Protocol v3.0 type definitions.
 * Source of truth — duplicated in spec at truststandardprotocol.org/spec/v3.
 *
 * v3 is intentionally separate from v2 (no shared types). v2 is being
 * deprecated; the hard break is documented in the protocol spec.
 */

export const TSP_V3_VERSION = "3.0" as const;

export type Sha256 = string;
export type Base64 = string;
export type ISO8601 = string;
export type UuidV7 = string;

// ─── Content ────────────────────────────────────────────────────────────

export type ContentType = "text" | "document" | "structured";

export interface Content {
  type: ContentType;
  value: string;
  hash: Sha256;
}

// ─── Declaration (Kilde + Paragraf-referanser) ──────────────────────────

export type SourceType =
  | "legal-database"
  | "government-website"
  | "official-document"
  | "academic-paper"
  | "verified-website"
  | "model-knowledge"
  | "user-input"
  | "unknown";

export interface PrimarySource {
  type: SourceType;
  url?: string;
  title: string;
  retrieved?: ISO8601;
}

export interface Citation {
  url: string;
  paragraph: string;
  quote: string;
  retrieved: ISO8601;
}

export interface Declaration {
  primarySource: PrimarySource;
  citations: Citation[];
}

// ─── Process (Modell + System-prompt) ───────────────────────────────────

export interface Model {
  name: string;
  version: string;
  provider: string;
  temperature: number;
  contextWindow: number;
}

export type SystemPromptField =
  | { hash: Sha256; text: string }
  | { hash: Sha256; redacted: true; reason: string };

export interface PipelineStep {
  name: string;
  durationMs?: number;
  meta?: Record<string, unknown>;
}

export interface Process {
  model: Model;
  systemPrompt: SystemPromptField;
  pipeline?: PipelineStep[];
}

// ─── Alignment (Usikkerhet + flagg) ─────────────────────────────────────

export type Severity = "low" | "med" | "high";

export interface UncertaintyEntry {
  field: string;
  reason: string;
  severity: Severity;
}

export interface AlignmentFlag {
  code: string;
  detail?: string;
}

export interface AlignmentPolicy {
  id: string;
  version: string;
}

export interface AlignmentRefusal {
  reason: string;
}

export interface Alignment {
  uncertainty: UncertaintyEntry[];
  flags?: AlignmentFlag[];
  humanReviewRequired: boolean;
  policy: AlignmentPolicy;
  refusal?: AlignmentRefusal;
}

// ─── Timestamp (RFC 3161 — TSA token in Phase 3) ────────────────────────

export interface Timestamp {
  claimed: ISO8601;
  tsaToken: Base64;
  tsaUrl: string;
}

// ─── Ledger ─────────────────────────────────────────────────────────────

export interface Ledger {
  id: UuidV7;
  prevHash: Sha256;
  hash: Sha256;
}

// ─── Signatures ─────────────────────────────────────────────────────────

export type SignatureRole = "instance" | "human-reviewer";
export type SignatureAlgorithm = "ed25519";

export interface SignatureEntry {
  role: SignatureRole;
  algorithm: SignatureAlgorithm;
  keyRef: string;
  signature: Base64;
  certChain: Base64[];
}

// ─── TrustEnvelope (root) ───────────────────────────────────────────────

export interface TrustEnvelope {
  tsp: typeof TSP_V3_VERSION;
  content: Content;
  declaration: Declaration;
  process: Process;
  alignment: Alignment;
  timestamp: Timestamp;
  ledger: Ledger;
  signatures: SignatureEntry[];
}

// ─── Verify result ──────────────────────────────────────────────────────

export type CheckStatus = "passed" | "failed" | "skipped" | "warning";

export interface CheckResult {
  status: CheckStatus;
  detail: string;
  evidence?: unknown;
}

export interface VerifyChecks {
  schema: CheckResult;
  contentHash: CheckResult;
  ledgerHash: CheckResult;
  manifestFetch: CheckResult;
  rootSignature: CheckResult;
  certChain: CheckResult;
  certValidity: CheckResult;
  revocation: CheckResult;
  tsa: CheckResult;
  dane?: CheckResult;
  signatures: CheckResult[];
}

export interface VerifyResult {
  valid: boolean;
  envelope: TrustEnvelope;
  checks: VerifyChecks;
  warnings: string[];
}
