/**
 * @lexitsp/sdk v4 · types — EXPERIMENTAL
 *
 * Reference types for RFC 0001 ("TSP as substrate"). Marked `4.0-draft` on
 * the wire until the RFC is accepted, per `SPEC-GOVERNANCE.md` §3.1.
 *
 * The core change vs v3: the AI-specific `process` field becomes a
 * discriminated union `provenance: Provenance` keyed on `kind`. The
 * cosmetically AI-flavoured `alignment` field is renamed to `qa`
 * (semantically identical). Everything else is bit-identical to v3.
 *
 * v4 reuses v3's substrate primitives (canonical JSON, hashing, signing,
 * manifest, TSA, revocation, DANE) without modification. That reuse is
 * itself the proof of substrate quality: the AI-specific code was a thin
 * layer over reusable primitives.
 */

import type {
  Sha256,
  Base64,
  ISO8601,
  UuidV7,
  ContentType,
  Content,
  SourceType,
  PrimarySource,
  Citation,
  Declaration,
  Model,
  SystemPromptField,
  PipelineStep,
  Severity,
  UncertaintyEntry,
  AlignmentFlag,
  AlignmentPolicy,
  AlignmentRefusal,
  Timestamp,
  Ledger,
  SignatureRole,
  SignatureAlgorithm,
  SignatureEntry,
  CheckStatus,
  CheckResult,
} from "../v3/types";

export type {
  Sha256,
  Base64,
  ISO8601,
  UuidV7,
  ContentType,
  Content,
  SourceType,
  PrimarySource,
  Citation,
  Declaration,
  Model,
  SystemPromptField,
  PipelineStep,
  Severity,
  UncertaintyEntry,
  AlignmentFlag,
  AlignmentPolicy,
  AlignmentRefusal,
  Timestamp,
  Ledger,
  SignatureRole,
  SignatureAlgorithm,
  SignatureEntry,
  CheckStatus,
  CheckResult,
};

/**
 * v4 wire version. Carries the `-draft` suffix until RFC 0001 is accepted
 * per §3.1 of the spec governance doc. The suffix is enforced at wrap
 * time so v4 envelopes cannot pretend to be a frozen standard while the
 * RFC is still open.
 */
export const TSP_V4_VERSION = "4.0-draft" as const;

// ─── Provenance — the substrate move ───────────────────────────────────

export type ProvenanceKind =
  | "ai"
  | "credential"
  | "attestation"
  | "supply-chain";

/**
 * `kind: "ai"` — identical semantics to v3 `Process`. Carried verbatim
 * so v3 → v4 migration for AI issuers is a pure field rename.
 */
export interface AiProvenance {
  kind: "ai";
  model: Model;
  systemPrompt: SystemPromptField;
  pipeline?: PipelineStep[];
}

/**
 * `kind: "credential"` — for diplomas, course completions, professional
 * certifications, and any "X was achieved by Y at time T" claim.
 *
 * Note: there is no free-text payload here. `criteria.id` is a stable
 * identifier the issuer publishes elsewhere (think OpenBadges criteria
 * URL or a course code in an institutional catalogue). This is
 * deliberate — Charter §11 (data minimization) extends to credentials.
 */
export interface CredentialIssuer {
  id: string;
  name: string;
  jurisdiction?: string;
}

export interface CredentialCriteria {
  id: string;
  name: string;
  meta?: Record<string, unknown>;
}

export interface CredentialProvenance {
  kind: "credential";
  issuer: CredentialIssuer;
  criteria: CredentialCriteria;
  achievedAt: ISO8601;
  validUntil?: ISO8601;
}

/**
 * `kind: "attestation"` — a general "I claim X happened" envelope for
 * cases that don't fit AI, credential, or supply-chain. Used sparingly;
 * if a domain emerges with enough volume, it gets its own kind via RFC.
 */
export interface AttestationActor {
  id: string;
  name: string;
}

export interface AttestationClaim {
  id: string;
  statement: string;
}

export interface AttestationBasis {
  type: "observation" | "computation" | "third-party";
  ref?: string;
}

export interface AttestationProvenance {
  kind: "attestation";
  attester: AttestationActor;
  claim: AttestationClaim;
  basis: AttestationBasis;
}

/**
 * `kind: "supply-chain"` — origin + transformation chain. The
 * `transformations[].inputs[]` field MAY reference other TSP envelopes
 * by `ledger.id`, but verifiers MUST NOT follow those references
 * during verification of the referencing envelope. Reference
 * resolution is a separate opt-in operation. See RFC 0001 §
 * "Security and Privacy Impact" for the rationale.
 */
export interface SupplyChainOrigin {
  id: string;
  location?: string;
}

export interface SupplyChainTransformation {
  id: string;
  by: string;
  at: ISO8601;
  inputs: string[];
}

export interface SupplyChainProvenance {
  kind: "supply-chain";
  origin: SupplyChainOrigin;
  transformations: SupplyChainTransformation[];
}

export type Provenance =
  | AiProvenance
  | CredentialProvenance
  | AttestationProvenance
  | SupplyChainProvenance;

/** Type guard helpers for the discriminated union. */
export function isAiProvenance(p: Provenance): p is AiProvenance {
  return p.kind === "ai";
}
export function isCredentialProvenance(p: Provenance): p is CredentialProvenance {
  return p.kind === "credential";
}
export function isAttestationProvenance(p: Provenance): p is AttestationProvenance {
  return p.kind === "attestation";
}
export function isSupplyChainProvenance(p: Provenance): p is SupplyChainProvenance {
  return p.kind === "supply-chain";
}

// ─── QA — renamed from v3 Alignment, semantically identical ────────────

export interface QA {
  uncertainty: UncertaintyEntry[];
  flags?: AlignmentFlag[];
  humanReviewRequired: boolean;
  policy: AlignmentPolicy;
  refusal?: AlignmentRefusal;
}

// ─── TrustEnvelope (root) ──────────────────────────────────────────────

export interface TrustEnvelope {
  tsp: typeof TSP_V4_VERSION;
  content: Content;
  declaration: Declaration;
  provenance: Provenance;
  qa: QA;
  timestamp: Timestamp;
  ledger: Ledger;
  signatures: SignatureEntry[];
}

// ─── Verify result ─────────────────────────────────────────────────────

export interface VerifyChecks {
  schema: CheckResult;
  contentHash: CheckResult;
  ledgerHash: CheckResult;
  provenanceKind: CheckResult;
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
