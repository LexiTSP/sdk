/**
 * Example 3 — TSP as substrate: a verifiable course credential
 *
 * EXPERIMENTAL · uses @lexitsp/sdk/v4 (RFC 0001 reference). The v4 wire
 * version is `4.0-draft` and MUST NOT be used for production issuance
 * while the RFC is open.
 *
 * What this does:
 *   1. Generates an ephemeral Ed25519 key pair (Web Crypto).
 *   2. Wraps a course-completion claim as a TSP v4 TrustEnvelope using
 *      the `credential` provenance kind — same wrap(), same signature
 *      math, same verifier as the AI case in example 1. Different kind,
 *      different audience.
 *   3. Verifies it locally.
 *
 * Why this matters:
 *   This is the proof that TSP's claim of being a "substrate" is
 *   architectural, not just marketing. If the same primitives produce
 *   verifiable envelopes for AI outputs and for course credentials,
 *   the protocol is a substrate by demonstration. See RFC 0001 for the
 *   rest of the registered kinds (attestation, supply-chain).
 */

import {
  generateKeyPair,
  exportPublicKeyJwk,
  sign,
  wrap,
  verifyLocal,
  credentialProfile,
  TSP_V4_VERSION,
} from "@lexitsp/sdk/v4";

const ZERO_HASH =
  "0000000000000000000000000000000000000000000000000000000000000000";

function line(label = "") {
  const bar = "─".repeat(60);
  if (label) console.log(`\n${bar}\n${label}\n${bar}`);
  else console.log(bar);
}

async function main() {
  line(`1 · Generate ephemeral issuer key (Ed25519). Wire version: ${TSP_V4_VERSION}`);
  const keyPair = await generateKeyPair();
  const publicKey = await exportPublicKeyJwk(keyPair.publicKey);

  line("2 · Issue a course-completion credential as a TrustEnvelope");
  const envelope = await wrap(
    {
      type: "document",
      value:
        "MGT-3010 Strategic Management · 7.5 ECTS · Grade C · 2026-06-12",
    },
    {
      signer: {
        keyRef: "did:web:bi.no#issuer-key-1",
        publicKey,
        certChain: [],
        sign: (data) => sign(keyPair.privateKey, data),
      },
      declaration: {
        primarySource: {
          type: "official-document",
          title: "BI Norwegian Business School transcript",
        },
        citations: [],
      },
      provenance: credentialProfile({
        issuer: {
          id: "did:web:bi.no",
          name: "BI Norwegian Business School",
          jurisdiction: "NO",
        },
        criteria: {
          id: "MGT-3010",
          name: "Strategic Management",
          meta: { ects: 7.5, passingGrade: "C" },
        },
        achievedAt: "2026-06-12T00:00:00Z",
      }),
      qa: {
        uncertainty: [],
        humanReviewRequired: false,
        policy: { id: "bi-credential-policy", version: "1" },
      },
      prevHash: ZERO_HASH,
      skipTsa: true,
    },
  );

  console.log("provenance.kind   ", envelope.provenance.kind);
  console.log("issuer            ", envelope.provenance.issuer.name);
  console.log("criteria          ", envelope.provenance.criteria.id);
  console.log("achievedAt        ", envelope.provenance.achievedAt);
  console.log("ledger.id         ", envelope.ledger.id);
  console.log("content.hash      ", envelope.content.hash);

  line("3 · verifyLocal() the credential envelope");
  const verified = await verifyLocal(envelope, { knownPublicKey: publicKey });
  console.log("valid             ", verified.valid);
  console.log("schema check      ", verified.checks.schema.status);
  console.log("provenanceKind    ", verified.checks.provenanceKind.status);
  console.log("contentHash check ", verified.checks.contentHash.status);
  console.log("ledgerHash check  ", verified.checks.ledgerHash.status);
  console.log(
    "signature check   ",
    verified.checks.signatures[0]?.status ?? "missing",
  );

  line();
  if (verified.valid) {
    console.log(
      "✓ Same SDK, same signature math, same verifier as example 1.",
    );
    console.log(
      "  Different kind, different audience. That is what substrate means.",
    );
  } else {
    console.log("⚠ Unexpected — investigate before trusting this example.");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Example failed:", err);
  process.exit(1);
});
