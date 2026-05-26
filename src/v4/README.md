# `@lexitsp/sdk/v4` — EXPERIMENTAL preview

> **This directory implements [TSP RFC 0001](https://github.com/LexiTSP/tsp-site/blob/main/docs/rfc/0001-tsp-as-substrate.md)
> as a working reference, not a production wire version.**
>
> It exists so the RFC isn't slideware. v4 envelopes carry
> `tsp: "4.0-draft"` (not `"4.0"`) precisely so they cannot be confused
> with a frozen standard while the RFC is still in the discussion
> window.

## Stability

| Aspect | Status |
| --- | --- |
| Wire version | `4.0-draft` — will become `4.0` only after RFC 0001 acceptance per `SPEC-GOVERNANCE.md` §3.1 |
| API surface | May change without notice while the RFC is open |
| Field names | May change without notice while the RFC is open |
| Signature mechanics | Final — reuses v3 substrate primitives |
| Canonical JSON | Final — reuses v3 substrate primitives |

## What v4 changes vs v3

- `process: Process` (AI-only struct) → `provenance: Provenance` (discriminated union by `kind`).
- `alignment: Alignment` (AI-flavoured naming) → `qa: QA` (semantically identical).
- Nothing else. `content`, `declaration`, `timestamp`, `ledger`, `signatures` are bit-identical to v3.

## What v4 reuses from v3 unchanged

Look at the imports in `envelope.ts` and `verify.ts` — every substrate
primitive comes from `../v3/`:

- Canonical JSON (`v3/canonical.ts`)
- SHA-256 (`v3/canonical-hash.ts`)
- Ed25519 (`v3/crypto.ts`)
- RFC 3161 TSA (`v3/tsa.ts`)
- Manifest/cert/revocation/DANE infrastructure (`v3/manifest-*.ts`, `v3/cert.ts`, `v3/revocation.ts`, `v3/dane.ts`)

**This reuse is the substrate property the RFC claims, made physically visible in the SDK layout.** If you can build a credential profile, an attestation profile, and a supply-chain profile on top of the same primitives that built the AI profile, the protocol is a substrate — by demonstration, not by marketing.

## Cross-version compatibility

`verifyAny()` dispatches on `envelope.tsp`:

- `"3.0"` → routes to v3's `verifyLocal`.
- `"4.0-draft"` → routes to v4's `verifyLocal`.
- anything else → returns `{ version: "unknown" }` with a reason.

v3 envelopes do not become invalid when v4 lands. v4 envelopes are not "valid v3" — they are a different wire version.

## Usage (preview)

```ts
import {
  wrap,
  verifyLocal,
  credentialProfile,
  generateKeyPair,
  exportPublicKeyJwk,
  sign,
} from "@lexitsp/sdk/v4";

const { publicKey, privateKey } = await generateKeyPair();
const pubJwk = await exportPublicKeyJwk(publicKey);

const envelope = await wrap(
  { type: "document", value: "Bachelor of Science, Computer Science" },
  {
    signer: {
      sign: (bytes) => sign(privateKey, bytes),
      publicKey: pubJwk,
      keyRef: "did:web:bi.no#issuer-key-1",
      certChain: [],
    },
    declaration: {
      primarySource: {
        type: "official-document",
        title: "BI Norwegian Business School transcript",
      },
      citations: [],
    },
    provenance: credentialProfile({
      issuer: { id: "did:web:bi.no", name: "BI Norwegian Business School" },
      criteria: { id: "MGT-3010", name: "Strategic Management" },
      achievedAt: "2026-06-12T00:00:00Z",
    }),
    qa: {
      uncertainty: [],
      humanReviewRequired: false,
      policy: { id: "bi-credential-policy", version: "1" },
    },
    prevHash: "GENESIS",
    skipTsa: true,
  },
);

const result = await verifyLocal(envelope, { knownPublicKey: pubJwk });
console.log(result.valid); // true
```

Same `wrap()`, same `verifyLocal()`, same signature math as the AI case. Different `kind`, different audience.

## What is deliberately NOT here yet

- Online verification (`verifyOnline`) for v4. The manifest layer is unchanged and will be wired in when the RFC is accepted.
- Risk-sink dual-write for v4 — out of scope until commercial-tier consumes v4.
- CLI entrypoint for v4 — keep `tsp` CLI on v3 until v4 is real.
- JSON-LD `@context` for v4 — pinned to `tsp-4.0-draft.jsonld` once the spec doc is drafted.

## How to give feedback

Per `SPEC-GOVERNANCE.md` §3.1:

1. Open an issue on `LexiTSP/tsp-site` with tag `rfc-proposal` referencing RFC 0001.
2. Or email `hello@truststandardprotocol.com`.
3. Charter-grounded objections are normative; aesthetic preferences are not.
