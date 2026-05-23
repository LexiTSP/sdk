import { J as JwkEd25519Public, f as Content, D as Declaration, i as Process, A as Alignment, q as TrustEnvelope, s as VerifyResult } from '../crypto-BK9EkNd3.js';
export { a as AlignmentFlag, B as Base64, C as CheckResult, d as CheckStatus, e as Citation, g as ContentType, I as ISO8601, K as KeyPair, L as Ledger, M as Model, P as PipelineStep, h as PrimarySource, S as Severity, j as Sha256, k as SignatureAlgorithm, l as SignatureEntry, m as SignatureRole, n as SourceType, o as SystemPromptField, T as TSP_V3_VERSION, p as Timestamp, U as UncertaintyEntry, r as UuidV7, V as VerifyChecks, t as exportPrivateKeyJwk, u as exportPublicKeyJwk, v as generateKeyPair, w as importPrivateKeyJwk, x as importPublicKeyJwk, y as sign, z as verifyEd25519 } from '../crypto-BK9EkNd3.js';
export { c as canonicalize, s as sha256Bytes, a as sha256Hex } from '../canonical-hash-D6poh0YE.js';
import { a as InstanceCertPayload, I as InstanceCertEntry, R as RevokedEntry, A as AcceptableAge, T as TrustManifest } from '../manifest-types-B9UOVg9n.js';
export { U as UnsignedManifest } from '../manifest-types-B9UOVg9n.js';

/**
 * @lexitsp/sdk v3 · envelope construction
 *
 * wrap() builds a TSP v3.0 TrustEnvelope, signs it, and (Phase 3) timestamps
 * it via an RFC 3161 TSA. If no TSA URLs are configured:
 *   - In production (NODE_ENV === "production"): wrap() throws.
 *   - In dev: a placeholder token "__phase1__" is used and a warning is logged.
 *
 * Construction order (corrected from Phase 1 spec):
 *   1. Compute content hash
 *   2. Build base envelope (placeholder tsaToken, empty signatures, empty ledger.hash)
 *   3. Compute signature over (envelope − signatures − ledger.hash − timestamp.tsaToken), set
 *   4. Compute TSA-input-hash = sha256(canonical(envelope − timestamp.tsaToken)),
 *      call TSA, set timestamp.tsaToken / tsaUrl / claimed (TSA's genTime)
 *   5. Compute ledger.hash over (envelope − ledger.hash) — now commits to real TSA token
 */

interface Signer {
    sign(data: Uint8Array): Promise<Uint8Array>;
    publicKey: JwkEd25519Public;
    keyRef: string;
    certChain: string[];
}
interface WrapInput {
    type: Content["type"];
    value: string;
}
interface WrapOptions {
    signer: Signer;
    declaration: Declaration;
    process: Process;
    alignment: Alignment;
    prevHash: string;
    /** Optional override for testing; defaults to current time. Used as fallback claimed when TSA unavailable. */
    now?: Date;
    /** TSA URLs in priority order. Required in production. Dev falls back to FreeTSA with warning. */
    tsaUrls?: string[];
    /** Per-TSA HTTP timeout (ms). Default 10000. */
    tsaTimeoutMs?: number;
    /** Override fetch (for testing). */
    fetch?: typeof globalThis.fetch;
    /** If true, skip TSA call and use placeholder token. Implicit in non-production when tsaUrls is empty. */
    skipTsa?: boolean;
    /**
     * Optional dual-write to a Risk-module endpoint. After the envelope is fully
     * constructed, fire-and-forget POST to riskSink.url with the envelope JSON.
     * Errors are handled per onError ("warn" | "throw" | "ignore"), default "warn".
     * Never blocks the primary wrap() return path.
     */
    riskSink?: RiskSinkConfig;
}
interface RiskSinkConfig {
    url: string;
    apiKey: string;
    onError?: "warn" | "throw" | "ignore";
    /** Override fetch (for testing). */
    fetch?: typeof globalThis.fetch;
}
declare const TSA_PLACEHOLDER_TOKEN = "__phase1__";
declare const TSA_PLACEHOLDER_URL = "https://placeholder.invalid/phase1";
declare function wrap(input: WrapInput, opts: WrapOptions): Promise<TrustEnvelope>;

/**
 * @lexitsp/sdk v3 · verify
 *
 * Phase 1 implements only the local-only path: schema + content hash +
 * ledger hash + signature. Manifest fetch, cert-chain, TSA, and DANE
 * are skipped (status: "skipped"). Phase 2/3 add those.
 */

interface VerifyLocalOptions {
    /** The public key to verify the instance signature against. */
    knownPublicKey: JwkEd25519Public;
}
declare function verifyLocal(envelope: TrustEnvelope, opts: VerifyLocalOptions): Promise<VerifyResult>;

/**
 * @lexitsp/sdk v3 · manifest signing
 */

interface RootSigner {
    sign(data: Uint8Array): Promise<Uint8Array>;
    publicKey: JwkEd25519Public;
}
interface InstanceCertSignInput {
    rootSigner: RootSigner;
    payload: InstanceCertPayload;
}
declare function signInstanceCert(input: InstanceCertSignInput): Promise<InstanceCertEntry>;
interface ManifestSignInput {
    rootSigner: RootSigner;
    organization: {
        name: string;
        domain: string;
    };
    instances: InstanceCertEntry[];
    revoked: RevokedEntry[];
    sequence: number;
    issuedAt: string;
    acceptableAge: AcceptableAge;
}
declare function signManifest(input: ManifestSignInput): Promise<TrustManifest>;

/**
 * @lexitsp/sdk v3 · manifest verification
 */

declare function verifyManifestSignature(manifest: TrustManifest): Promise<boolean>;
declare function verifyInstanceCert(cert: InstanceCertEntry, rootKey: JwkEd25519Public): Promise<boolean>;

/**
 * @lexitsp/sdk v3 · manifest fetch
 *
 * In-memory LRU + ETag conditional revalidation.
 */

declare function clearManifestCache(): void;
interface FetchManifestOptions {
    fetch?: typeof globalThis.fetch;
    ttlMs?: number;
    maxEntries?: number;
}
interface FetchManifestResult {
    manifest: TrustManifest;
    etag?: string;
    fromCache: boolean;
    revalidated: boolean;
    fetchedAt: number;
}
declare function fetchManifest(url: string, opts?: FetchManifestOptions): Promise<FetchManifestResult>;

/**
 * @lexitsp/sdk v3 · cert validity
 */

interface CertValidityResult {
    valid: boolean;
    reason?: string;
}
declare function isCertValidAt(cert: InstanceCertEntry, isoTime: string): CertValidityResult;

/**
 * @lexitsp/sdk v3 · revocation
 */

type RevocationResult = {
    status: "not-revoked";
    detail: string;
} | {
    status: "predates-revocation";
    detail: string;
} | {
    status: "revoked";
    detail: string;
};
declare function checkRevocation(instanceId: string, envelopeTime: string, revoked: RevokedEntry[]): RevocationResult;
interface PruneOptions {
    now: string;
    acceptableAgeSeconds: number;
    graceDays: number;
}
declare function pruneRevoked(revoked: RevokedEntry[], opts: PruneOptions): RevokedEntry[];

/**
 * @lexitsp/sdk v3 · sequence state
 *
 * Tracks the highest-sequence manifest seen per organization domain
 * to detect rollback attacks.
 */
declare function clearSequenceState(): void;
interface SequenceCheckResult {
    rollback: boolean;
    highestSeen: number | null;
    received: number;
}
declare function checkSequence(domain: string, sequence: number): SequenceCheckResult;
declare function recordSequence(domain: string, sequence: number): void;

/**
 * @lexitsp/sdk v3 · TSA trust list
 *
 * Per spec decision Q3.4/B: explicit cert-fingerprint whitelist.
 *
 * The SDK ships with EMPTY default trust list. Operators must explicitly
 * configure trusted TSAs via verifyOnline(env, { trustedTsas: [...] }) or
 * by passing a custom list. This is charter §6 honest:  we don't claim
 * trust we haven't earned via inspection.
 *
 * To obtain a fingerprint for a TSA cert:
 *   openssl x509 -in tsa.crt -fingerprint -sha256 -noout
 * Strip the colons and lowercase the result.
 *
 * For development, use addTrustedTsa() at process startup or pass via opts.
 */
interface TrustedTsa {
    /** Human-readable name, e.g. "Buypass TSA". Used in verify-result messages. */
    name: string;
    /** SHA-256 hex digest of the TSA's cert (DER), lowercase, no separators. */
    certFingerprintSha256: string;
    /** Optional notes (eIDAS-qualified? prod-vs-dev? etc.) */
    notes?: string;
}
/**
 * SDK default is intentionally empty per charter §6. Operators must
 * configure their trust posture explicitly.
 */
declare const DEFAULT_TRUSTED_TSAS: TrustedTsa[];
/**
 * Compute the SHA-256 fingerprint of a TSA cert (DER bytes).
 * Returns lowercase hex with no separators.
 */
declare function fingerprintCert(certDer: Uint8Array): Promise<string>;
declare function isTrustedTsaCert(certDer: Uint8Array, trustList?: TrustedTsa[]): Promise<{
    trusted: boolean;
    matched?: TrustedTsa;
}>;

/**
 * @lexitsp/sdk v3 · DNS DANE via DNS-over-HTTPS
 *
 * Per spec decision Q3.3/A, DANE is verifier-side only and opt-in.
 * We use DoH (Cloudflare default) to get DNSSEC validation via the AD flag.
 */

interface DaneOptions {
    dohEndpoint?: string;
    fetch?: typeof globalThis.fetch;
    timeoutMs?: number;
}
interface DaneResult {
    valid: boolean;
    reason: string;
    manifestUrlFromDns?: string;
}
declare function verifyDane(domain: string, manifestRootKey: JwkEd25519Public, opts?: DaneOptions): Promise<DaneResult>;

/**
 * @lexitsp/sdk v3 · verifyOnline
 *
 * Full network-aware verification.
 * Fail-closed on network errors per spec decision Q2.3/B.
 */

interface VerifyOnlineOptions {
    fetch?: typeof globalThis.fetch;
    ttlMs?: number;
    acceptableManifestAgeOverride?: number;
    requireDane?: boolean;
    /** Per Phase 3 Q3.2/C: opt-in for legacy alpha envelopes with placeholder tsaToken. */
    acceptLegacyTsa?: boolean;
    /** Per Phase 3 Q3.4/B: explicit TSA cert-fingerprint trust list. Default empty. */
    trustedTsas?: TrustedTsa[];
    /** Options forwarded to verifyDane when requireDane is true. */
    daneOptions?: DaneOptions;
}
declare function verifyOnline(envelope: TrustEnvelope, opts?: VerifyOnlineOptions): Promise<VerifyResult>;

/**
 * @lexitsp/sdk v3 · RFC 3161 TSA client
 *
 * Sequential multi-TSA fallback per spec decision Q3.5/A.
 * Sends TimeStampReq, receives TimeStampResp, returns base64-encoded token
 * plus TSA-attested time and which TSA actually responded.
 */
interface BuildTimeStampReqOptions {
    hash: Uint8Array;
    nonce: bigint;
    certReq: boolean;
}
declare function buildTimeStampReq(opts: BuildTimeStampReqOptions): Uint8Array;
interface TsaClientOptions {
    /** TSA URLs in priority order; first-success-wins. */
    urls: string[];
    /** Per-TSA timeout in ms. Default 10_000. */
    timeoutMs?: number;
    /** Override fetch (testing). */
    fetch?: typeof globalThis.fetch;
}
interface TsaStampResult {
    /** Base64-encoded TimeStampToken (the entire ContentInfo). */
    token: string;
    /** URL of the TSA that successfully responded. */
    tsaUrl: string;
    /** TSA-attested production time (ISO8601). */
    genTime: string;
}
declare function stampHash(hash: Uint8Array, opts: TsaClientOptions): Promise<TsaStampResult>;

/**
 * @lexitsp/sdk v3 · TSA token verification
 *
 * Verifies an RFC 3161 TimeStampToken:
 *   1. Parse token, extract TSTInfo + TSA cert + signature
 *   2. Verify messageImprint hash matches expected
 *   3. Verify TSA cert fingerprint is in trust list
 *   4. Import cert SPKI as Web Crypto key, verify signature over signedAttrs
 */

interface VerifyTsaResult {
    valid: boolean;
    genTime?: string;
    tsaName?: string;
    reason: string;
}
declare function verifyTsaToken(tokenBase64: string, expectedHash: Uint8Array, trustList?: TrustedTsa[]): Promise<VerifyTsaResult>;

export { AcceptableAge, Alignment, type CertValidityResult, Content, DEFAULT_TRUSTED_TSAS, type DaneOptions, type DaneResult, Declaration, type FetchManifestOptions, type FetchManifestResult, InstanceCertEntry, InstanceCertPayload, type InstanceCertSignInput, JwkEd25519Public, type ManifestSignInput, Process, type PruneOptions, type RevocationResult, RevokedEntry, type RootSigner, type SequenceCheckResult, type Signer, TSA_PLACEHOLDER_TOKEN, TSA_PLACEHOLDER_URL, TrustEnvelope, TrustManifest, type TrustedTsa, type TsaClientOptions, type TsaStampResult, type VerifyLocalOptions, type VerifyOnlineOptions, VerifyResult, type VerifyTsaResult, type WrapInput, type WrapOptions, buildTimeStampReq, checkRevocation, checkSequence, clearManifestCache, clearSequenceState, fetchManifest, fingerprintCert, isCertValidAt, isTrustedTsaCert, pruneRevoked, recordSequence, signInstanceCert, signManifest, stampHash, verifyDane, verifyInstanceCert, verifyLocal, verifyManifestSignature, verifyOnline, verifyTsaToken, wrap };
