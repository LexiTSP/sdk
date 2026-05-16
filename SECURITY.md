# Security Policy

Please report suspected vulnerabilities privately to LexiCo AS at hello@lexico.no.

Do not open public GitHub issues for vulnerabilities, private keys, signing material, manifest compromise, verifier bypasses, or package supply-chain issues.

For public alpha, the supported package line is:

- `@lexitsp/sdk@3.0.0-alpha.6`

Security-sensitive surfaces include envelope signing, local verification, online verification, manifest handling, revocation, TSA validation, DANE discovery, and sequence-state rollback checks.

The default trusted TSA list is intentionally empty until a real provider has been inspected and fingerprint-validated.
