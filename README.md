# `@lexitsp/sdk`

> Trust Standard Protocol v3 alpha — sign AI outputs as cryptographically
> verifiable `TrustEnvelope`s and verify them locally or online without
> trusting any vendor dashboard.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TSP v3.0 alpha](https://img.shields.io/badge/TSP-v3.0--alpha-1E3A5F.svg)](https://truststandardprotocol.com/spec)
[![npm](https://img.shields.io/badge/npm-@lexitsp%2Fsdk@alpha-cb3837.svg)](https://www.npmjs.com/package/@lexitsp/sdk)

The Trust Standard Protocol (TSP) gives every important AI output a signed
receipt — what was said, which source and process produced it, when it
happened, and whether anyone changed it later. The protocol is open
([CC-BY-4.0](https://truststandardprotocol.com/spec)); this SDK is the
reference TypeScript implementation ([MIT](./LICENSE)).

This package is sovereign by default. You can sign and verify envelopes
without any LexiCo infrastructure. Online verification can additionally
check manifests, certificate chains, revocation, RFC 3161 timestamps and
DANE when those are configured.

The public canonical site is <https://truststandardprotocol.com>.

---

## 5-minute path

```bash
npm install @lexitsp/sdk@alpha
# or: bun add @lexitsp/sdk@alpha
```

```ts
import {
  exportPublicKeyJwk,
  generateKeyPair,
  sign,
  verifyLocal,
  wrap,
} from "@lexitsp/sdk/v3";

const keyPair = await generateKeyPair();
const publicKey = await exportPublicKeyJwk(keyPair.publicKey);

const envelope = await wrap(
  { type: "text", value: "The answer is based on the cited policy section." },
  {
    signer: {
      keyRef: "https://example.com/.well-known/tsp-manifest.json#instance-1",
      publicKey,
      certChain: [],
      sign: (data) => sign(keyPair.privateKey, data),
    },
    declaration: {
      primarySource: { type: "document", title: "Policy handbook" },
      citations: [],
    },
    process: {
      model: {
        provider: "example",
        name: "example-model",
        version: "1",
        temperature: 0,
        contextWindow: 8192,
      },
      systemPrompt: { hash: "0".repeat(64) },
    },
    alignment: {
      uncertainty: [],
      humanReviewRequired: false,
      policy: { id: "default", version: "1.0" },
    },
    prevHash: "0".repeat(64),
    // skipTsa: dev only — production envelopes MUST configure tsaUrls.
    skipTsa: true,
  },
);

const result = await verifyLocal(envelope, { knownPublicKey: publicKey });
console.log(result.valid);                       // true
console.log(result.checks.contentHash.status);   // "passed"
```

Change one character of `envelope.content.value` and re-run `verifyLocal()`
— `result.valid` is now `false` and `checks.contentHash.status` is
`"failed"`. That is the whole sales point in one motion.

Running, self-contained versions of this flow (plus an EU AI Act
flavoured walk-through) live in [`examples/`](./examples).

---

## What this SDK is for

TSP exists because the painful question almost always arrives **after** the
AI answer has already moved:

- Was this the exact answer the customer, citizen, employee or reviewer saw?
- Was it edited after generation?
- Which source, model, policy, timestamp and manifest produced it?
- Can a third party verify the artifact without trusting the vendor dashboard?

For each AI output that needs to survive that question, this SDK gives you:

1. `wrap(...)` — turn the output into a signed v3 `TrustEnvelope`
   (Ed25519 + SHA-256 + RFC 8785 canonical JSON, with optional RFC 3161
   TSA stamp and DANE binding).
2. `verifyLocal(...)` — check schema, content hash, ledger hash and
   signature without any network.
3. `verifyOnline(...)` — additionally check manifest, certificate chain,
   revocation, TSA token and DANE.
4. A `tsp` CLI for keygen, instance-cert issuance and manifest publishing.

Mapped against the EU AI Act, the same artifact does work for:

- **Art. 12 (record-keeping)** — `ledger.id` + `ledger.prevHash` +
  `ledger.hash` give an append-only chain whose history cannot be silently
  rewritten.
- **Art. 13 (transparency to users)** — `declaration.primarySource` +
  `declaration.citations` carry the cited evidence.
- **Art. 14 (human oversight)** — `alignment.humanReviewRequired` and the
  reviewer signature role.
- **Art. 15 (accuracy / robustness)** — `process.model`,
  `process.systemPrompt(.hash)` and `alignment.uncertainty`.
- **Art. 50 (transparency obligations, applicable from 2 August 2026)** —
  `content.value` + `content.hash` carry the exact answer the user saw.

See [`examples/02-eu-ai-act`](./examples/02-eu-ai-act) for a worked
end-to-end walk-through.

---

## Status

`@lexitsp/sdk@3.0.0-alpha.6` is the reference TypeScript implementation
for the public TSP alpha. It is frozen as the **TSP Spec 1.0 Candidate
implementation** until an external organization signs a `TrustEnvelope`
with its own key and DNS-hosted `https://<domain>/.well-known/tsp-manifest.json`
(Gate A — see the [public org profile](https://github.com/LexiTSP)).

Sovereign by default. The MIT licence and the CC-BY-4.0 spec together
mean: even if LexiCo disappears, your implementation keeps working.

### Experimental: `@lexitsp/sdk/v4` (RFC 0001 preview)

A separate `src/v4/` subtree implements the reference for
[RFC 0001 — "TSP as substrate"](https://github.com/LexiTSP/tsp-site/blob/main/docs/rfc/0001-tsp-as-substrate.md).
It carries wire version `4.0-draft` and is intentionally not yet
recommended for production issuance. The proposal turns the AI-only
`process` field into a `provenance: Provenance` discriminated union so
the same SDK, manifest layer, and verifier can attest credentials,
attestations and supply-chain claims — not only AI outputs.

If you want to play with it, see
[`examples/03-substrate-credential/`](./examples/03-substrate-credential/)
or read [`src/v4/README.md`](./src/v4/README.md). Feedback goes through
the RFC process documented in
[`SPEC-GOVERNANCE.md`](https://github.com/LexiTSP/tsp-site/blob/main/docs/SPEC-GOVERNANCE.md).

---

## Online verification

```ts
import { verifyOnline } from "@lexitsp/sdk/v3";

const result = await verifyOnline(envelope, {
  trustedTsas: [],   // configure only after fingerprint review
});
```

Production guidance:

- Host a stable signed TSP manifest at `https://<your-domain>/.well-known/tsp-manifest.json`.
- Configure real `tsaUrls` when wrapping production envelopes.
- Configure `trustedTsas` only after inspecting and documenting the TSA
  certificate fingerprint. The default trusted list is intentionally empty.
- Do not use placeholder TSA tokens or `skipTsa` for production claims.

---

## CLI

The package exposes a `tsp` binary:

```bash
npx tsp --help
npx tsp keygen --org "Example AS" --domain "example.com" --out root.jwk
npx tsp issue-instance --root root.jwk --id instance-1 --out instance.jwk
npx tsp publish-manifest --root root.jwk --instances ./instances --out tsp-manifest.json
```

---

## Public API surface

Primary v3 exports from `@lexitsp/sdk/v3`:

- `wrap`, `verifyLocal`, `verifyOnline`
- `generateKeyPair`, `exportPublicKeyJwk`, `importPublicKeyJwk`, `sign`
- manifest helpers (`signInstanceCert`, `signManifest`,
  `verifyManifestSignature`, `verifyInstanceCert`)
- TSA helpers (`stampHash`, `verifyTsaToken`, `DEFAULT_TRUSTED_TSAS`)
- DANE helpers (`verifyDane`)
- revocation and sequence-state helpers

Node-only utilities are available from `@lexitsp/sdk/node`.

---

## Interop fixtures

The public site repo ships `fixtures/v3.0` as TSP Spec 1.0 Candidate test
vectors. The interop check is also runnable directly:

```bash
git clone https://github.com/LexiTSP/tsp-site
cd tsp-site
bun run check:interop
```

The **Gate A** external-adopter criterion requires the adopter's own key
and `https://<domain>/.well-known/tsp-manifest.json`. Localhost or
LexiCo-hosted manifests do not count.

---

## Companion packages

- [`@lexitsp/trustbadge-react`](https://github.com/LexiTSP/trustbadge-react)
  — drop-in React component to show the receipt and verification state to
  end users.
- [`LexiTSP/tsp-site`](https://github.com/LexiTSP/tsp-site) — public site,
  spec, fixtures and browser verifier source.

---

## Protocol docs and useful URLs

- Spec: <https://truststandardprotocol.com/spec>
- API reference: <https://truststandardprotocol.com/docs>
- Browser verifier (paste an envelope, see it verify or fail): <https://truststandardprotocol.com/verify>
- Playground (sign in the browser, then tamper): <https://truststandardprotocol.com/playground>
- Canonical manifest: <https://truststandardprotocol.com/.well-known/tsp-manifest.json>
- EU AI Act campaign and downloads: <https://truststandardprotocol.com/ai-act-august-2>

---

## Security

Report suspected vulnerabilities privately — see [`SECURITY.md`](./SECURITY.md).
Sensitive areas include envelope construction, signature verification,
manifest discovery, instance certificate issuance, revocation, TSA
verification and DANE.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). Contributions must preserve
the sovereign-by-default property: the local verification path must not
depend on any LexiCo-hosted service.

## Licence

MIT for this SDK; CC-BY-4.0 for the TSP specification text.

## Contact

LexiCo AS · Tønsberg, Norway · <https://truststandardprotocol.com> · tsp@lexico.no
