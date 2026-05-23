/**
 * Example 1 — Minimal wrap + verify + tamper
 *
 * What this does:
 *   1. Generates an ephemeral Ed25519 key pair (Web Crypto).
 *   2. Wraps a short AI answer as a TSP v3 TrustEnvelope.
 *   3. Verifies the envelope locally (no network needed).
 *   4. Changes one character in the content and verifies again — the check
 *      now fails because the SHA-256 content hash and the Ed25519 signature
 *      no longer match.
 *
 * Why this matters:
 *   This is the floor of what TSP gives you. Without writing a line of
 *   cryptography yourself, an AI output that you produced becomes something
 *   anyone with the public key can later inspect and either trust or reject.
 */

import {
  generateKeyPair,
  exportPublicKeyJwk,
  sign,
  verifyLocal,
  wrap,
} from "@lexitsp/sdk/v3";

const ZERO_HASH =
  "0000000000000000000000000000000000000000000000000000000000000000";

function line(label = "") {
  const bar = "─".repeat(60);
  if (label) console.log(`\n${bar}\n${label}\n${bar}`);
  else console.log(bar);
}

async function main() {
  line("1 · Generate ephemeral signing key (Ed25519, Web Crypto)");
  const keyPair = await generateKeyPair();
  const publicKey = await exportPublicKeyJwk(keyPair.publicKey);
  console.log("public key (JWK)\n", publicKey);

  line("2 · Wrap an AI answer as a TrustEnvelope");
  const envelope = await wrap(
    {
      type: "text",
      value:
        "Based on the policy handbook, the customer qualifies for compensation under section 4.2.",
    },
    {
      signer: {
        keyRef: "ephemeral://example#instance",
        publicKey,
        certChain: [],
        sign: (data) => sign(keyPair.privateKey, data),
      },
      declaration: {
        primarySource: {
          type: "document",
          title: "Example policy handbook",
        },
        citations: [],
      },
      process: {
        model: {
          provider: "example",
          name: "example-model",
          version: "1.0.0",
          temperature: 0,
          contextWindow: 8192,
        },
        systemPrompt: {
          // For the minimal example we omit the prompt text and only commit
          // its hash. In production you would either include it or document
          // why it is redacted.
          hash: ZERO_HASH,
        },
      },
      alignment: {
        uncertainty: [],
        humanReviewRequired: false,
        policy: { id: "default", version: "1.0" },
      },
      prevHash: ZERO_HASH,
      // The example never reaches the network — skip the RFC 3161 TSA stamp.
      // Production envelopes must configure tsaUrls; see ../../README.md.
      skipTsa: true,
    },
  );

  console.log("ledger.id         ", envelope.ledger.id);
  console.log("content.hash      ", envelope.content.hash);
  console.log("signature (b64)   ", envelope.signatures[0].signature.slice(0, 32) + "…");

  const sigStatus = (result) =>
    result.checks.signatures[0]?.status ?? "missing";

  line("3 · verifyLocal() the envelope as is");
  const verified = await verifyLocal(envelope, { knownPublicKey: publicKey });
  console.log("valid             ", verified.valid);
  console.log("contentHash check ", verified.checks.contentHash.status);
  console.log("ledgerHash check  ", verified.checks.ledgerHash.status);
  console.log("signature check   ", sigStatus(verified));

  line("4 · Tamper: change one character in the content and re-verify");
  const tampered = JSON.parse(JSON.stringify(envelope));
  tampered.content.value = tampered.content.value.replace(
    "qualifies",
    "does not qualify",
  );

  const reVerified = await verifyLocal(tampered, { knownPublicKey: publicKey });
  console.log("valid             ", reVerified.valid);
  console.log("contentHash check ", reVerified.checks.contentHash.status);
  console.log("ledgerHash check  ", reVerified.checks.ledgerHash.status);
  console.log("signature check   ", sigStatus(reVerified));

  line();
  if (verified.valid && !reVerified.valid) {
    console.log("✓ Working as designed: the original verifies, the tampered copy does not.");
  } else {
    console.log("⚠ Unexpected result — investigate before trusting this example.");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Example failed:", err);
  process.exit(1);
});
