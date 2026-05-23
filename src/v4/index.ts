/**
 * @lexitsp/sdk/v4 — entrypoint for Trust Standard Protocol v4.0-draft.
 *
 * EXPERIMENTAL — reference implementation for RFC 0001 ("TSP as
 * substrate"). NOT for production issuance. See `./README.md` for the
 * stability boundary.
 *
 * Stable substrate primitives (canonical JSON, SHA-256, Ed25519,
 * manifest, TSA, revocation, DANE) are re-exported from v3 and are
 * unchanged by RFC 0001. That reuse is the substrate property the RFC
 * claims, made physically visible in the SDK layout.
 */

// Wire version
export { TSP_V4_VERSION } from "./types";

// Types — v4-specific shape
export type {
  TrustEnvelope,
  Provenance,
  ProvenanceKind,
  AiProvenance,
  CredentialProvenance,
  CredentialIssuer,
  CredentialCriteria,
  AttestationProvenance,
  AttestationActor,
  AttestationClaim,
  AttestationBasis,
  SupplyChainProvenance,
  SupplyChainOrigin,
  SupplyChainTransformation,
  QA,
  VerifyChecks,
  VerifyResult,
} from "./types";

// Types — re-exported substrate (unchanged from v3)
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
} from "./types";

// Type guards
export {
  isAiProvenance,
  isCredentialProvenance,
  isAttestationProvenance,
  isSupplyChainProvenance,
} from "./types";

// Issuance + verification
export { wrap, TSA_PLACEHOLDER_TOKEN, TSA_PLACEHOLDER_URL } from "./envelope";
export type { Signer, WrapInput, WrapOptions } from "./envelope";

export { verifyLocal, verifyAny } from "./verify";
export type { VerifyLocalOptions } from "./verify";

// Profile helpers
export { aiProfile } from "./profiles/ai";
export type { AiProfileInput } from "./profiles/ai";
export { credentialProfile } from "./profiles/credential";
export type { CredentialProfileInput } from "./profiles/credential";
export { attestationProfile } from "./profiles/attestation";
export type { AttestationProfileInput } from "./profiles/attestation";
export { supplyChainProfile } from "./profiles/supply-chain";
export type { SupplyChainProfileInput } from "./profiles/supply-chain";

// Substrate primitives — re-exported from v3 unchanged
export { canonicalize } from "../v3/canonical";
export { sha256Hex, sha256Bytes } from "../v3/canonical-hash";
export {
  generateKeyPair,
  sign,
  verify as verifyEd25519,
  exportPublicKeyJwk,
  importPublicKeyJwk,
  exportPrivateKeyJwk,
  importPrivateKeyJwk,
} from "../v3/crypto";
export type { KeyPair, JwkEd25519Public } from "../v3/crypto";
