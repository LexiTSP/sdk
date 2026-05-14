/**
 * @lexitsp/sdk/v3 — entrypoint for Trust Standard Protocol v3.0.
 *
 * Phase 1 (alpha.1): local-only signing and verification.
 * Phase 2 (alpha.2): manifest + PKI infrastructure, verifyOnline, CLI.
 * Phase 3 (alpha.3): RFC 3161 TSA, DNS DANE.
 */

export { TSP_V3_VERSION } from "./types";
export type {
  Alignment,
  AlignmentFlag,
  Base64,
  CheckResult,
  CheckStatus,
  Citation,
  Content,
  ContentType,
  Declaration,
  ISO8601,
  Ledger,
  Model,
  PipelineStep,
  PrimarySource,
  Process,
  Severity,
  Sha256,
  SignatureAlgorithm,
  SignatureEntry,
  SignatureRole,
  SourceType,
  SystemPromptField,
  Timestamp,
  TrustEnvelope,
  UncertaintyEntry,
  UuidV7,
  VerifyChecks,
  VerifyResult,
} from "./types";

export { canonicalize } from "./canonical";
export { sha256Hex, sha256Bytes } from "./canonical-hash";
export {
  generateKeyPair,
  sign,
  verify as verifyEd25519,
  exportPublicKeyJwk,
  importPublicKeyJwk,
  exportPrivateKeyJwk,
  importPrivateKeyJwk,
} from "./crypto";
export type { KeyPair, JwkEd25519Public } from "./crypto";
export { wrap } from "./envelope";
export type { Signer, WrapInput, WrapOptions } from "./envelope";
export { verifyLocal } from "./verify";
export type { VerifyLocalOptions } from "./verify";

// Phase 2 additions
export type {
  TrustManifest,
  InstanceCertEntry,
  RevokedEntry,
  AcceptableAge,
  UnsignedManifest,
  InstanceCertPayload,
} from "./manifest-types";

export {
  signInstanceCert,
  signManifest,
} from "./manifest-sign";
export type {
  RootSigner,
  InstanceCertSignInput,
  ManifestSignInput,
} from "./manifest-sign";

export {
  verifyManifestSignature,
  verifyInstanceCert,
} from "./manifest-verify";

export {
  fetchManifest,
  clearManifestCache,
} from "./manifest-fetch";
export type {
  FetchManifestOptions,
  FetchManifestResult,
} from "./manifest-fetch";

export { isCertValidAt } from "./cert";
export type { CertValidityResult } from "./cert";

export {
  checkRevocation,
  pruneRevoked,
} from "./revocation";
export type {
  RevocationResult,
  PruneOptions,
} from "./revocation";

export {
  checkSequence,
  recordSequence,
  clearSequenceState,
} from "./sequence-state";
export type { SequenceCheckResult } from "./sequence-state";

export { verifyOnline } from "./verify-online";
export type { VerifyOnlineOptions } from "./verify-online";

// Phase 3 additions
export { TSA_PLACEHOLDER_TOKEN, TSA_PLACEHOLDER_URL } from "./envelope";

export { stampHash, buildTimeStampReq } from "./tsa";
export type { TsaClientOptions, TsaStampResult } from "./tsa";

export { verifyTsaToken } from "./tsa-verify";
export type { VerifyTsaResult } from "./tsa-verify";

export {
  fingerprintCert,
  isTrustedTsaCert,
  DEFAULT_TRUSTED_TSAS,
} from "./tsa-trust";
export type { TrustedTsa } from "./tsa-trust";

export { verifyDane } from "./dane";
export type { DaneOptions, DaneResult } from "./dane";
