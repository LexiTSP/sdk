# AGENTS.md

## Cursor Cloud specific instructions

This is a single-package TypeScript SDK (`@lexitsp/sdk`) — no long-running services, databases, or Docker required.

### Runtime

- **Bun** is the package manager and runtime (lockfile: `bun.lock`).
- Bun must be on `$PATH`. The update script installs it if missing; ensure `~/.bun/bin` is in `PATH` (`export PATH="$HOME/.bun/bin:$PATH"`).

### Key commands

| Task | Command |
|------|---------|
| Install deps | `bun install` |
| Build | `bun run build` |
| Test | `bun run test` |
| CLI help | `bun bin/tsp.mjs --help` |

### Notes

- Tests run via **Vitest** (config in `vitest.config.ts`); all tests are in `test/**/*.test.ts` with a 10 s timeout.
- Build uses **tsup** and emits ESM + `.d.ts` to `dist/`.
- No external network calls are needed — all crypto runs in-process (Web Crypto Ed25519 + SHA-256). Network-dependent features (TSA, DANE, manifests) are mocked in tests.
- The `examples/` directory contains runnable demos; each has its own `package.json` that depends on `@lexitsp/sdk`. Run `bun install` inside an example directory, then `node index.mjs`.
- There is no lint script in `package.json`. TypeScript type-checking (`bunx tsc --noEmit`) serves as the lint equivalent.
