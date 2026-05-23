# 01 · Minimal wrap + verify + tamper

The smallest possible end-to-end TSP example. Takes a string, wraps it in a
signed `TrustEnvelope`, verifies it, and then shows what happens when one
character is changed after signing.

## Run it

```bash
npm install
node index.mjs
```

You should see four blocks: key generation, envelope construction, a
successful local verification, and then a failed verification after a
single-character tamper.

## What it shows

| You see this | Meaning |
| --- | --- |
| The envelope has a `ledger.id`, a `content.hash` and a `signatures[0].signature` | The output is now an inspectable artifact, not just text. |
| `verifyLocal()` returns `valid: true` | The content hash and the Ed25519 signature both match. |
| After tampering, `verifyLocal()` returns `valid: false` and `contentHash` is `failed` | The receipt is broken — anyone holding the public key will know the artifact is no longer the one that was signed. |

## What it deliberately does not do

- It does **not** call an RFC 3161 timestamp authority (`skipTsa: true`).
- It does **not** publish a manifest at `/.well-known/tsp-manifest.json`.
- It does **not** persist the envelope anywhere.

For a more realistic flow with the AI Act-relevant `declaration`,
`process` and `alignment` fields filled in, see
[`../02-eu-ai-act/`](../02-eu-ai-act).

For the same idea in a browser, run the
[public verifier](https://truststandardprotocol.com/verify) or the
[playground](https://truststandardprotocol.com/playground).
