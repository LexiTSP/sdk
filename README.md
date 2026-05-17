# @lexitsp/sdk

> Trust Standard Protocol v3 alpha: sign AI outputs as cryptographically verifiable `TrustEnvelope`s and verify signatures, hashes and manifests locally or online.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TSP v3.0 alpha](https://img.shields.io/badge/TSP-v3.0--alpha-1E3A5F.svg)](https://truststandardprotocol.com/spec)

## Status

`@lexitsp/sdk@3.0.0-alpha.6` is the reference TypeScript implementation for the public TSP alpha. It is frozen as the TSP Spec 1.0 Candidate implementation until an external organization signs a TrustEnvelope with its own key and DNS-hosted manifest.

The SDK is sovereign by default: you can sign and verify envelopes without LexiCo infrastructure. Online verification can add manifest, certificate, revocation, TSA and DANE checks when those services are configured.

## Install

```bash
npm install @lexitsp/sdk@alpha
# or
bun add @lexitsp/sdk@alpha
```

## Browser / Web Runtime Quickstart

```ts
import { exportPublicKeyJwk, generateKeyPair, sign, verifyLocal, wrap } from "@lexitsp/sdk/v3";

const keyPair = await generateKeyPair();
const publicKey = await exportPublicKeyJwk(keyPair.publicKey);

const envelope = await wrap(
  {
    type: "text",
    value: "The answer is based on the cited policy section.",
  },
  {
    signer: {
      keyRef: "https://truststandardprotocol.com/.well-known/tsp-manifest.json#example-instance",
      publicKey,
      certChain: [],
      sign: (data) => sign(keyPair.privateKey, data),
    },
    declaration: {
      primarySource: {
        type: "document",
        title: "Policy handbook",
      },
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
      systemPrompt: {
        hash: "0000000000000000000000000000000000000000000000000000000000000000",
      },
    },
    alignment: {
      uncertainty: [],
      humanReviewRequired: false,
      policy: {
        id: "default",
        version: "1.0",
      },
    },
    prevHash: "0000000000000000000000000000000000000000000000000000000000000000",
    skipTsa: true,
  },
);

const result = await verifyLocal(envelope, {
  knownPublicKey: publicKey,
});

console.log(result.valid);
console.log(result.checks.contentHash.status);
```

Local verification checks schema, content hash, ledger hash and signature. It intentionally skips manifest, cert-chain, revocation, TSA and DANE.

## Online Verification

```ts
import { verifyOnline } from "@lexitsp/sdk/v3";

const result = await verifyOnline(envelope, {
  trustedTsas: [],
});
```

Production guidance:

- Host a stable signed TSP manifest.
- Configure real `tsaUrls` when wrapping production envelopes.
- Configure `trustedTsas` only after inspecting and documenting the TSA certificate fingerprint.
- Do not use placeholder TSA tokens or `skipTsa` for production claims.

## CLI

The package exposes the `tsp` binary:

```bash
npx tsp --help
npx tsp keygen --org "Example AS" --domain "example.com" --out root.jwk
npx tsp issue-instance --root root.jwk --id instance-1 --out instance.jwk
npx tsp publish-manifest --root root.jwk --instances ./instances --out tsp-manifest.json
```

## Public API

Primary v3 exports are available from `@lexitsp/sdk/v3`:

- `wrap`
- `verifyLocal`
- `verifyOnline`
- `generateKeyPair`
- `exportPublicKeyJwk`
- `sign`
- manifest helpers
- TSA helpers
- DANE helpers
- revocation and sequence-state helpers

Node-only utilities are available from `@lexitsp/sdk/node`.

## Protocol Docs

- Spec: https://truststandardprotocol.com/spec
- API reference: https://truststandardprotocol.com/docs
- Browser verifier: https://truststandardprotocol.com/verify
- Manifest: https://truststandardprotocol.com/.well-known/tsp-manifest.json
- Playground for building/signing envelopes: https://truststandardprotocol.com/playground
- AI Act campaign downloads: https://truststandardprotocol.com/ai-act-august-2

## Interop Fixtures

The public workspace includes `fixtures/v3.0` as TSP Spec 1.0 Candidate test vectors, revision 1. They can be validated without importing the SDK:

```bash
bun run check:interop
```

The Gate A external-adopter criterion requires the adopter's own key and `https://<domain>/.well-known/tsp-manifest.json`; localhost or LexiCo-hosted manifests do not count.

## License

MIT. The TSP specification is published under CC-BY 4.0.

## Contact

LexiCo AS · Tønsberg, Norway · https://truststandardprotocol.com · tsp@lexico.no
