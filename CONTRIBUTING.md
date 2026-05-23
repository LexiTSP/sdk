# Contributing to `@lexitsp/sdk`

Thank you for helping improve the Trust Standard Protocol.

## Project rules

Three rules carry the project. Any contribution that breaks one of them
will not be merged.

1. **Sovereign by default.** Local signing and verification (`wrap`,
   `verifyLocal`) must not depend on LexiCo-hosted infrastructure. The
   open layer must keep working in a network-isolated environment.
2. **No silent trust.** Trust roots (TSAs, manifests, certificate
   anchors) must be explicit. `DEFAULT_TRUSTED_TSAS` is empty by design;
   defaults that grant trust without documented review will be rejected.
3. **Claims match code.** Public-facing copy in README, npm metadata,
   and CHANGELOG must describe what the code actually does. Alpha is
   alpha; "production-ready" is reserved for verified, post-Gate-A use.

## Before you open a PR

- Run the test suite:

  ```bash
  bun install
  bun run test     # vitest run
  ```

- For protocol-level changes, **open an issue first** so the spec, SDK,
  fixtures and verifier behaviour stay aligned. Protocol changes that
  break wire compatibility will not land in the alpha line.

- For changes that touch security-critical paths (canonicalization,
  signature construction or verification, manifest handling, TSA / DANE,
  CLI key generation) include test vectors and a short rationale in the
  PR description.

- For documentation changes, prefer concrete language over marketing
  metaphor. The site copy follows the same discipline.

## Areas where help is especially welcome

- Clean-room interop implementations in other languages (Rust, Python,
  Go). These directly move TSP from "spec + reference impl" to "open
  standard with multiple implementations".
- Additional realistic examples beyond [`examples/`](./examples) — e.g.
  Annex IV-style evidence flows, multi-signer envelopes, hardware-token
  reviewer keys, browser-only end-to-end demos.
- Hardening the CLI: better keygen UX, manifest publishing helpers,
  rotation workflows.
- Security review and threat-model write-ups.

## Code style

The SDK is intentionally small and explicit. Prefer obvious code over
clever abstractions, especially around cryptography and canonicalization.

## Reporting security issues

Do **not** report security issues in public. See [`SECURITY.md`](./SECURITY.md).

## Contact

LexiCo AS · Tønsberg, Norway · <https://truststandardprotocol.com> · tsp@lexico.no
