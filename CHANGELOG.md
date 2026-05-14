# Changelog

All notable changes to `@lexitsp/sdk` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 3.0.0-alpha.4 — 2026-04-30

### Added
- `Alignment.policy` (required) and `Alignment.refusal` (optional) — structured fields needed by Risk module signal extraction.
- `WrapOptions.riskSink` — fire-and-forget dual-write of envelope to a Risk-module endpoint after construction. Never blocks `wrap()` return.
- `RiskSinkConfig` interface with `onError: "warn" | "throw" | "ignore"` (default `"warn"`).

### Changed
- `Alignment` schema is breaking in alpha: any envelope built without `alignment.policy` will fail TypeScript checks. Existing fixtures updated.

### Notes
- Lays the groundwork for `@lexitsp/risk-server` (sub-project III.1).
- 101 tests passing (97 prior + 4 new for riskSink).

## 3.0.0-alpha.3 — 2026-04-30

### Added
- Phase 3: RFC 3161 TSA + DNS DANE.
- Hand-rolled minimal ASN.1 BER/DER decoder (`asn1.ts`) — no third-party crypto deps.
- `stampHash()` — RFC 3161 TSA client with sequential multi-TSA fallback (Q3.5/A).
- `buildTimeStampReq()` — TimeStampReq builder.
- `verifyTsaToken()` — verifies TSA token signature against fingerprint-whitelisted cert (Q3.4/B).
- `tsa-trust.ts` — explicit TSA trust list. SDK ships with empty default per charter §6 honesty.
- `verifyDane()` — DNS DANE TXT lookup via DNS-over-HTTPS (Cloudflare default), DNSSEC AD-flag required.
- `wrap()` extended: `tsaUrls` option, calls real TSA when configured. Production guard: throws if no TSA in `NODE_ENV=production`.
- `verifyOnline()` extended: real TSA token verification, optional DANE check, `acceptLegacyTsa` flag for alpha-envelope backward-compat (Q3.2/C).
- TSA-attested time replaces local `Date.now()` in `envelope.timestamp.claimed` when TSA stamp succeeds.
- `wrap()` construction order corrected: TSA stamp now happens BEFORE `ledger.hash` computation, so `ledger.hash` commits to the real TSA token.

### Changed
- `TSA_PLACEHOLDER_TOKEN` constant exported. Envelopes still using it must opt-in to verification via `acceptLegacyTsa: true`.

### Notes
- Sub-prosjekt I (Protocol v3.0) is now feature-complete. Pending: production hardening, real-TSA integration tests against Buypass/Sectigo.
- `DEFAULT_TRUSTED_TSAS` is empty by design; integrators must configure trust explicitly.
- Hybrid Ed25519 + ML-DSA (post-quantum) deferred to v3.x.

## 3.0.0-alpha.2 — 2026-04-30

### Added
- Phase 2: Manifest + PKI infrastructure.
- `TrustManifest` schema with org-root signature, instance certs, revocation list, sequence-based rollback protection, and signed `issuedAt` + `acceptableAge` for staleness rejection.
- `signInstanceCert()`, `signManifest()` — manifest signing helpers.
- `verifyManifestSignature()`, `verifyInstanceCert()` — verification helpers.
- `fetchManifest()` — HTTP fetch with LRU + ETag conditional revalidation.
- `isCertValidAt()` — validity-window check.
- `checkRevocation()` + `pruneRevoked()` — revocation logic with formal pruning rule (revocations older than `acceptableAge + grace` are dropped).
- `checkSequence()` / `recordSequence()` — sequence-state for rollback detection.
- `verifyOnline()` — full network-aware verification pipeline. Fail-closed on network errors per spec decision Q2.3/B.
- `tsp` CLI: `keygen`, `issue-instance`, `publish-manifest`, `verify` subcommands. Flags-only (no config files) per spec decision Q2.4/A.
- `@lexitsp/sdk/v3/admin` subpath for programmatic admin operations (HSM/KMS-friendly).

### Notes
- TSA verification (RFC 3161) and DNS DANE remain Phase 3.
- v3 envelopes still carry placeholder `tsaToken` field; this becomes a real token in Phase 3.
- v2.x remains the stable production export.

## 3.0.0-alpha.1 — 2026-04-29

### Added
- `@lexitsp/sdk/v3` subpath: TSP Protocol v3.0 — Phase 1 (schema + local-only sign/verify).
- RFC 8785-strict `canonicalize()` for v3.
- Ed25519 primitives via Web Crypto (`generateKeyPair`, `sign`, `verify`, JWK import/export).
- `wrap()` with pluggable `Signer` interface — supports file-based keys (default) and HSM/KMS (plug your own signer).
- `verifyLocal()` — granular check-list result with per-check status; manifest/TSA/cert-chain checks skipped (Phase 2/3 will implement).
- Property-based test coverage via fast-check.

### Notes
- v2.x remains the stable production export (`@lexitsp/sdk`). v3 is alpha.
- Phase 2 (manifest + PKI) and Phase 3 (TSA + DANE) are not yet shipped.
- v3 envelopes have a placeholder `tsaToken` until Phase 3.

## [2.0.0] — 2026-04-22

Initial public release as a standalone npm package, extracted into the standalone TSP
production codebase where TSP has run since March 2026.

### Added
- `tsp.wrap(content, config, options?)` for envelope construction
- `tsp.verify(envelope)` and `tsp.verifyChain(envelopes)` for verification
- `tsp.toJsonLd(envelope)` for JSON-LD serialization
- `FileLedger` class under `@lexitsp/sdk/node` for append-only JSONL persistence
- Deterministic confidence scoring (`computeConfidenceScore`, `classifyLevel`)
- `canonicalJson` utility for cross-platform reproducible serialization
- Full TypeScript types exported as both runtime and type definitions
- MIT license

### Specification
- Implements TSP v2.0 — see [truststandardprotocol.org/spec](https://truststandardprotocol.org/spec)
- Compatible with envelopes produced by other v2.0 conformant implementations
- Hash algorithm: SHA-256 over canonical JSON
- Score weights: source 0.5, process 0.3, alignment 0.2

### Notes
- Requires Node 18+ or Bun 1.0+ (uses Web Crypto API)
- Browser-compatible for `wrap`, `verify`, `verifyChain` (not `FileLedger`)
- Zero runtime dependencies except `nanoid` for envelope IDs
