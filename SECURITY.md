# Security Policy

The Trust Standard Protocol (TSP) treats verification, signing material
and manifest discovery as security-critical.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** to LexiCo AS at
**security@truststandardprotocol.com**. We will acknowledge within five working days.

For non-security matters (questions, pilots, integration support) use
the general TSP channel at **hello@truststandardprotocol.com** instead.

Do **not** open public GitHub issues for any of the following:

- private signing keys or any other secret material;
- envelope forgery, signature bypass, or manifest poisoning;
- canonicalization or hashing bypasses;
- CLI key-handling issues that could leak private material;
- supply-chain or package-integrity issues against `@lexitsp/sdk`.

## Supported versions

For the public alpha the supported package line is:

| Package | Supported |
| --- | --- |
| `@lexitsp/sdk@3.0.0-alpha.6` | yes |
| earlier alphas | best effort, please upgrade |

When the project reaches the TSP Spec 1.0 release the supported version
matrix will be updated here.

## Trust roots and defaults

- The default trusted TSA list (`DEFAULT_TRUSTED_TSAS`) ships **empty**.
  Integrators must configure their own trusted TSAs after inspecting and
  documenting the relevant certificate fingerprints.
- `wrap(..., { skipTsa: true })` and the placeholder TSA token are
  acceptable for development and tests only. The SDK refuses to skip the
  TSA stamp when `NODE_ENV=production` and no `tsaUrls` are configured.
- `verifyLocal()` is intentionally offline. It does not fetch manifests,
  validate certificate chains, check revocation, verify TSA tokens, or
  perform DANE checks. Use `verifyOnline()` when those network checks are
  required.

## Coordinated disclosure

We follow a 90-day coordinated-disclosure window from the date a fix
ships. Acknowledged reporters who wish to be credited will be listed in
the project changelog and on <https://truststandardprotocol.com>.
