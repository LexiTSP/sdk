# Contributing

Thanks for helping improve TSP.

Before opening a PR:

1. Keep public claims aligned with the implementation.
2. Do not add trusted TSA defaults without documented certificate/fingerprint review.
3. Keep the SDK sovereign by default; verification must not depend on LexiCo infrastructure.
4. Run `bun run --cwd packages/lexitsp-sdk vitest run`.

For protocol-level changes, open an issue first so the spec, SDK and verifier
behavior stay aligned.
