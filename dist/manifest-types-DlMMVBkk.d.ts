/**
 * @lexitsp/sdk v3 · types
 *
 * Trust Standard Protocol v3.0 type definitions.
 * Source of truth — duplicated in spec at truststandardprotocol.com/spec/v3.
 *
 * v3 is intentionally separate from v2 (no shared types). v2 is being
 * deprecated; the hard break is documented in the protocol spec.
 */
declare const TSP_V3_VERSION: "3.0";
type Sha256 = string;
type Base64 = string;
type ISO8601 = string;
type UuidV7 = string;
type ContentType = "text" | "document" | "structured";
interface Content {
    type: ContentType;
    value: string;
    hash: Sha256;
}
type SourceType = "legal-database" | "government-website" | "official-document" | "academic-paper" | "verified-website" | "model-knowledge" | "user-input" | "unknown";
interface PrimarySource {
    type: SourceType;
    url?: string;
    title: string;
    retrieved?: ISO8601;
}
interface Citation {
    url: string;
    paragraph: string;
    quote: string;
    retrieved: ISO8601;
}
interface Declaration {
    primarySource: PrimarySource;
    citations: Citation[];
}
interface Model {
    name: string;
    version: string;
    provider: string;
    temperature: number;
    contextWindow: number;
}
type SystemPromptField = {
    hash: Sha256;
    text: string;
} | {
    hash: Sha256;
    redacted: true;
    reason: string;
};
interface PipelineStep {
    name: string;
    durationMs?: number;
    meta?: Record<string, unknown>;
}
interface Process {
    model: Model;
    systemPrompt: SystemPromptField;
    pipeline?: PipelineStep[];
}
type Severity = "low" | "med" | "high";
interface UncertaintyEntry {
    field: string;
    reason: string;
    severity: Severity;
}
interface AlignmentFlag {
    code: string;
    detail?: string;
}
interface AlignmentPolicy {
    id: string;
    version: string;
}
interface AlignmentRefusal {
    reason: string;
}
interface Alignment {
    uncertainty: UncertaintyEntry[];
    flags?: AlignmentFlag[];
    humanReviewRequired: boolean;
    policy: AlignmentPolicy;
    refusal?: AlignmentRefusal;
}
interface Timestamp {
    claimed: ISO8601;
    tsaToken: Base64;
    tsaUrl: string;
}
interface Ledger {
    id: UuidV7;
    prevHash: Sha256;
    hash: Sha256;
}
type SignatureRole = "instance" | "human-reviewer";
type SignatureAlgorithm = "ed25519";
interface SignatureEntry {
    role: SignatureRole;
    algorithm: SignatureAlgorithm;
    keyRef: string;
    signature: Base64;
    certChain: Base64[];
}
interface TrustEnvelope {
    tsp: typeof TSP_V3_VERSION;
    content: Content;
    declaration: Declaration;
    process: Process;
    alignment: Alignment;
    timestamp: Timestamp;
    ledger: Ledger;
    signatures: SignatureEntry[];
}
type CheckStatus = "passed" | "failed" | "skipped" | "warning";
interface CheckResult {
    status: CheckStatus;
    detail: string;
    evidence?: unknown;
}
interface VerifyChecks {
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
interface VerifyResult {
    valid: boolean;
    envelope: TrustEnvelope;
    checks: VerifyChecks;
    warnings: string[];
}

/**
 * Ed25519 primitives via Web Crypto API.
 *
 * Compatible with Node 18+, Bun 1+, modern browsers, and edge runtimes.
 * No external crypto dependencies.
 */
interface KeyPair {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
}
interface JwkEd25519Public {
    kty: "OKP";
    crv: "Ed25519";
    x: string;
    alg?: "EdDSA";
    use?: "sig";
    kid?: string;
}
declare function generateKeyPair(): Promise<KeyPair>;
declare function sign(privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array>;
declare function verify(publicKey: CryptoKey, signature: Uint8Array, data: Uint8Array): Promise<boolean>;
declare function exportPublicKeyJwk(publicKey: CryptoKey): Promise<JwkEd25519Public>;
declare function importPublicKeyJwk(jwk: JwkEd25519Public): Promise<CryptoKey>;
declare function importPrivateKeyJwk(jwk: JsonWebKey): Promise<CryptoKey>;
declare function exportPrivateKeyJwk(privateKey: CryptoKey): Promise<JsonWebKey>;

/**
 * @lexitsp/sdk v3 · manifest types
 *
 * TrustManifest is the well-known artifact that maps an organization
 * to its rooted key infrastructure. It is signed by the org-root and
 * contains the active instance certificates plus a revocation list.
 */

interface InstanceCertEntry {
    id: string;
    publicKey: JwkEd25519Public;
    validFrom: ISO8601;
    validUntil: ISO8601;
    rootSignature: Base64;
}
interface RevokedEntry {
    id: string;
    revokedAt: ISO8601;
    reason: string;
}
interface AcceptableAge {
    seconds: number;
}
interface TrustManifest {
    tsp: "3.0";
    organization: {
        name: string;
        domain: string;
    };
    rootKey: JwkEd25519Public;
    instances: InstanceCertEntry[];
    revoked: RevokedEntry[];
    sequence: number;
    issuedAt: ISO8601;
    acceptableAge: AcceptableAge;
    rootSignatureOverManifest: Base64;
}
type UnsignedManifest = Omit<TrustManifest, "rootSignatureOverManifest">;
type InstanceCertPayload = Omit<InstanceCertEntry, "rootSignature">;

export { type AcceptableAge as A, type Base64 as B, type CheckResult as C, type Declaration as D, importPublicKeyJwk as E, sign as F, verify as G, type ISO8601 as I, type JwkEd25519Public as J, type KeyPair as K, type Ledger as L, type Model as M, type PipelineStep as P, type RevokedEntry as R, type Severity as S, TSP_V3_VERSION as T, type UncertaintyEntry as U, type VerifyChecks as V, type Alignment as a, type AlignmentFlag as b, type CheckStatus as c, type Citation as d, type Content as e, type ContentType as f, type InstanceCertEntry as g, type InstanceCertPayload as h, type PrimarySource as i, type Process as j, type Sha256 as k, type SignatureAlgorithm as l, type SignatureEntry as m, type SignatureRole as n, type SourceType as o, type SystemPromptField as p, type Timestamp as q, type TrustEnvelope as r, type TrustManifest as s, type UnsignedManifest as t, type UuidV7 as u, type VerifyResult as v, exportPrivateKeyJwk as w, exportPublicKeyJwk as x, generateKeyPair as y, importPrivateKeyJwk as z };
