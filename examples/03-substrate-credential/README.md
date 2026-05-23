# 03 · TSP as substrate — a verifiable course credential

> **EXPERIMENTAL.** This example uses `@lexitsp/sdk/v4`, the reference
> implementation for [TSP RFC 0001 ("TSP as substrate")](https://github.com/LexiTSP/tsp-site/blob/main/docs/rfc/0001-tsp-as-substrate.md).
> The v4 wire version is `4.0-draft` and MUST NOT be used for production
> issuance while the RFC is in its discussion window.

Same wrap, same signature math, same verifier as [example 1](../01-minimal-wrap-verify) — but for a non-AI claim: "this student completed this course at this institution on this date."

## Run it

```bash
npm install
node index.mjs
```

You should see three blocks: key generation, credential issuance, and a successful local verification.

## What it shows

| You see this | Meaning |
| --- | --- |
| `provenance.kind = "credential"` | The envelope uses the credential profile, not the AI profile. |
| `issuer`, `criteria.id`, `achievedAt` are the only domain-specific fields | Charter §11 (data minimization) applies to credentials too — no free-text grade narrative, no student PII in the envelope. |
| `verifyLocal()` returns `valid: true` | The exact same verifier that accepts AI envelopes accepts this one. That is what "substrate" means architecturally. |

## What this proves about the protocol

Compare the imports of [example 1's `index.mjs`](../01-minimal-wrap-verify/index.mjs) with this one:

```diff
- import { ..., wrap, verifyLocal } from "@lexitsp/sdk/v3";
+ import { ..., wrap, verifyLocal, credentialProfile, TSP_V4_VERSION } from "@lexitsp/sdk/v4";
```

Everything else — key generation, canonical JSON, SHA-256, Ed25519 — is *the same code*, reused from `v3/` unchanged. The AI-specific part of v3 was a thin layer; the protocol underneath is substrate. RFC 0001 proposes formalising that.

## What the registry of `kind` values currently includes

| `kind` | Use | Helper |
| --- | --- | --- |
| `"ai"` | AI outputs (the original v3 use case) | `aiProfile()` |
| `"credential"` | Diplomas, course completions, professional certifications | `credentialProfile()` (this example) |
| `"attestation"` | General "I claim X happened" envelopes | `attestationProfile()` |
| `"supply-chain"` | Origin + transformation chains | `supplyChainProfile()` |

New kinds require their own RFC (see [`spec/provenance-kinds.md`](https://github.com/LexiTSP/tsp-site) when it lands).

## What this example deliberately does not do

- It does **not** call an RFC 3161 timestamp authority (`skipTsa: true`).
- It does **not** publish a manifest at `/.well-known/tsp-manifest.json`.
- It does **not** persist the envelope anywhere.
- It does **not** suggest you should issue v4 envelopes in production yet — read the RFC first.

## When v4 stops being experimental

When RFC 0001 meets the acceptance criteria in `SPEC-GOVERNANCE.md` §3.1:

1. Reference implementation lands and is green in CI. **(this directory)**
2. At least one fixture per `provenance.kind` is canonical and verifies against an independent re-implementation.
3. 14-day open-discussion window passes with no charter-grounded veto.
4. A `spec/TSP-4.0.md` artefact exists and matches the reference implementation byte-for-byte on the four canonical fixtures.

At that point the wire version flips from `4.0-draft` to `4.0` and this directory loses the EXPERIMENTAL banner.
