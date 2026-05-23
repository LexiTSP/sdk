# 02 · Wrapping a regulated AI answer for EU AI Act evidence

A realistic example. A fictional Nordic insurance company "NordTrygg" runs
an internal assistant that answers customers about EU Regulation 261/2004
flight-delay compensation. The answer goes out today. Six months from now a
regulator or internal auditor wants to verify exactly what the AI said,
which sources it cited, which model produced it, and whether anyone touched
the answer afterwards.

TSP turns that question from a forensic exercise into a one-shot
cryptographic check.

## Run it

```bash
npm install
node index.mjs     # build, sign, save envelope.json + envelope.tampered.json
node verify.mjs    # verify both files locally
```

`index.mjs` prints a regulator-facing summary that shows which AI Act
articles each TrustEnvelope field is doing work for. `verify.mjs` then
reads the saved files and verifies them, showing that the tampered copy
fails.

## Field-by-field reading

| Envelope field | What it carries | Article it speaks to |
| --- | --- | --- |
| `content.value` + `content.hash` | The exact answer the customer saw, plus a SHA-256 of that answer. | Art. 50 (transparency from 2 Aug 2026), Art. 13 (transparency to deployers/users). |
| `declaration.primarySource` | A pointer to the legal text the answer is grounded in (EUR-Lex). | Art. 13. |
| `declaration.citations[]` | Specific paragraph + quote that the answer relied on. | Art. 13. |
| `process.model` | Provider, model name, version, temperature, context window. | Art. 12 (record-keeping), Art. 15 (accuracy/robustness). |
| `process.systemPrompt.hash` | SHA-256 of the system prompt (or the redacted hash) — the exact instructions that produced this answer can be reconstructed or proven. | Art. 12, Art. 15. |
| `alignment.policy` | Which internal policy version was in effect. | Art. 9 (risk management), Art. 17 (quality management). |
| `alignment.uncertainty` | Structured uncertainty / refusal flags. | Art. 15. |
| `alignment.humanReviewRequired` | Whether a human-in-the-loop was needed. | Art. 14. |
| `timestamp.claimed` (and `tsaToken` in production) | When the envelope was produced. RFC 3161 TSA token makes the time independently verifiable. | Art. 12. |
| `ledger.id`, `ledger.prevHash`, `ledger.hash` | Append-only chain of envelopes — rewriting history is mathematically detectable. | Art. 12. |
| `signatures[0]` | Ed25519 signature over the canonicalized envelope. | Art. 12; binds the answer to the signing organization. |

## What this example deliberately does not do

- It uses an **ephemeral key pair** generated at run time. A production
  issuer would generate keys with the CLI and publish a manifest at
  `https://<your-domain>/.well-known/tsp-manifest.json`.
- It **skips the RFC 3161 timestamp authority** (`skipTsa: true`) so the
  example runs fully offline. Production envelopes must configure
  `tsaUrls` and a reviewed `trustedTsas` list.
- It includes only one citation and a placeholder system prompt hash.
  Real claims pipelines will typically have richer `declaration.citations`
  and either a full system prompt or a redacted hash with an explicit
  reason.

## Going further

- Pair this example with [`@lexitsp/trustbadge-react`](https://github.com/LexiTSP/trustbadge-react)
  to show the same receipt to the end user.
- Run the [browser verifier](https://truststandardprotocol.com/verify) on
  `envelope.json` for the same verification with a UI.
- See the [public spec](https://truststandardprotocol.com/spec) for the
  normative schema and the canonical surface
  (`/.well-known/tsp-manifest.json`, RFC 8785 canonicalization, RFC 3161
  TSA tokens, DANE).
