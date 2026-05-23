# `@lexitsp/sdk` examples

Two self-contained examples that you can run with nothing but Node.js 18+
(or Bun 1.x). Each example installs only `@lexitsp/sdk@alpha` and is meant
to be read end-to-end in 2-3 minutes.

| # | Folder | What it shows | Time |
| --- | --- | --- | --- |
| 1 | [`01-minimal-wrap-verify/`](./01-minimal-wrap-verify) | Wrap a string, verify it locally, change one character, watch verification fail. The smallest TSP can be. | < 5 min |
| 2 | [`02-eu-ai-act/`](./02-eu-ai-act) | Wrap a realistic regulated AI answer with full `declaration`, `process`, `alignment` and `ledger` fields. Save the envelope to disk and walk an auditor through it field by field, mapped to the relevant EU AI Act articles. | 10-15 min |

## Running an example

```bash
cd examples/01-minimal-wrap-verify
npm install
node index.mjs
```

Or with Bun:

```bash
cd examples/01-minimal-wrap-verify
bun install
bun run index.mjs
```

Each example uses Web Crypto (built into Node 18+ and every modern browser), so
nothing native needs to be compiled.

## What these examples deliberately do not do

- They do **not** contact LexiCo infrastructure.
- They **skip** the RFC 3161 TSA stamp (`skipTsa: true`) so the example runs
  fully offline. Production envelopes must configure a real TSA. See
  [Production guidance](../README.md#online-verification) and the
  [TSA section of the spec](https://truststandardprotocol.com/spec).
- They use ephemeral keys (`generateKeyPair`) rather than a published
  `/.well-known/tsp-manifest.json`. For real issuance, generate keys with the
  CLI (`npx tsp keygen ...`) and publish a manifest at a stable HTTPS URL.

These examples are intentionally the *floor* of what TSP can do. The
[browser verifier](https://truststandardprotocol.com/verify) and the
[playground](https://truststandardprotocol.com/playground) show the same
flow with full network-backed checks enabled.
