/**
 * Example 2 — Wrapping a regulated AI answer for EU AI Act evidence
 *
 * This is a realistic scenario: an internal assistant at a fictional Nordic
 * insurance company "NordTrygg" answers a customer about EU Regulation
 * 261/2004 flight-delay compensation. The answer goes out today, and six
 * months from now a regulator or auditor wants to verify exactly what the
 * AI said, where the answer came from, which model produced it, and that
 * nobody touched the answer afterwards.
 *
 * TSP turns that question from a forensics exercise into a one-shot
 * cryptographic check.
 *
 * Articles the fields below map to (high-level — not legal advice):
 *   - Art. 12 (Record-keeping)        → ledger.id + ledger.prevHash + ledger.hash
 *   - Art. 13 (Transparency to users) → declaration.primarySource + declaration.citations
 *   - Art. 14 (Human oversight)       → alignment.humanReviewRequired (+ reviewer signature when used)
 *   - Art. 15 (Accuracy / robustness) → process.model + process.systemPrompt + alignment.uncertainty
 *   - Art. 50 (Transparency obligations from 2 Aug 2026)
 *                                     → content.value + content.hash carry the exact answer the user saw.
 *
 * This script:
 *   1. Generates an ephemeral Ed25519 key pair.
 *   2. Builds a realistic TrustEnvelope around an AI answer.
 *   3. Writes it to ./envelope.json and ./envelope.tampered.json.
 *   4. Prints a regulator-facing summary.
 *
 * `node verify.mjs` then verifies both files locally and shows that the
 * tampered file is rejected.
 */

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  generateKeyPair,
  exportPublicKeyJwk,
  sign,
  wrap,
} from "@lexitsp/sdk/v3";

const here = dirname(fileURLToPath(import.meta.url));
const out = (name) => resolve(here, name);
const ZERO_HASH =
  "0000000000000000000000000000000000000000000000000000000000000000";

// ---------------------------------------------------------------------------
// The fictional AI answer that we want to make verifiable.
// ---------------------------------------------------------------------------

const customerAnswer = {
  type: "text",
  value:
    "You qualify for €600 compensation under EU Regulation 261/2004 Article 7(1)(c) " +
    "because your flight covered more than 3,500 km and arrived more than 4 hours late. " +
    "Submit your claim within three years using the form linked below.",
};

// ---------------------------------------------------------------------------
// 1. Declaration — what source the answer was grounded in (Art. 13)
// ---------------------------------------------------------------------------

const declaration = {
  primarySource: {
    type: "legal-database",
    url: "https://eur-lex.europa.eu/eli/reg/2004/261/oj",
    title: "Regulation (EC) No 261/2004 — Air passenger rights",
    retrieved: "2026-05-23T08:12:04Z",
  },
  citations: [
    {
      url: "https://eur-lex.europa.eu/eli/reg/2004/261/oj",
      title: "Regulation (EC) No 261/2004",
      paragraph: "Article 7(1)(c)",
      quote:
        "EUR 600 for all flights not falling under (a) or (b) — i.e. flights over 3,500 km " +
        "with arrival delay of four hours or more.",
    },
  ],
};

// ---------------------------------------------------------------------------
// 2. Process — what produced the answer (Art. 12 + 15)
// ---------------------------------------------------------------------------

const process = {
  model: {
    provider: "example-eu-host",
    name: "example-instruct",
    version: "2026-04",
    temperature: 0,
    contextWindow: 32_000,
  },
  // In production you either include the full system prompt or commit only
  // its hash with an explicit redaction reason. Here we hash a placeholder
  // string so the example is reproducible.
  systemPrompt: {
    hash: await sha256Hex(
      "You are NordTrygg's claims assistant. Always cite EU regulations by ELI.",
    ),
  },
  // Optional: any pipeline steps that produced the answer (RAG, tool calls,
  // etc.). Omitted from this example for brevity.
};

// ---------------------------------------------------------------------------
// 3. Alignment — uncertainty, refusal, policy, human-review (Art. 14 + 15)
// ---------------------------------------------------------------------------

const alignment = {
  uncertainty: [],
  humanReviewRequired: false,
  policy: { id: "nordtrygg.customer-claims", version: "2026.05" },
};

// ---------------------------------------------------------------------------
// Build, sign, save.
// ---------------------------------------------------------------------------

const keyPair = await generateKeyPair();
const publicKey = await exportPublicKeyJwk(keyPair.publicKey);

const envelope = await wrap(customerAnswer, {
  signer: {
    keyRef: "ephemeral://nordtrygg-example#instance-1",
    publicKey,
    certChain: [],
    sign: (data) => sign(keyPair.privateKey, data),
  },
  declaration,
  process,
  alignment,
  prevHash: ZERO_HASH,
  // Skip the TSA stamp so the example runs fully offline. Production
  // envelopes MUST configure tsaUrls; see ../../README.md.
  skipTsa: true,
});

const envelopePath = out("envelope.json");
writeFileSync(envelopePath, JSON.stringify(envelope, null, 2), "utf8");

const publicKeyPath = out("public-key.json");
writeFileSync(publicKeyPath, JSON.stringify(publicKey, null, 2), "utf8");

// Make a tampered copy for the verifier script to reject.
const tampered = JSON.parse(JSON.stringify(envelope));
tampered.content.value = tampered.content.value.replace(
  "€600 compensation",
  "€0 compensation",
);
writeFileSync(
  out("envelope.tampered.json"),
  JSON.stringify(tampered, null, 2),
  "utf8",
);

// ---------------------------------------------------------------------------
// Regulator-facing summary
// ---------------------------------------------------------------------------

const line = (s = "") => console.log(s);
line("Trust Standard Protocol — EU AI Act demo envelope");
line("--------------------------------------------------");
line(`Ledger ID            ${envelope.ledger.id}`);
line(`Content hash         ${envelope.content.hash}`);
line(`Signature algorithm  ${envelope.signatures[0].algorithm}`);
line(`Key ref              ${envelope.signatures[0].keyRef}`);
line(`Claimed timestamp    ${envelope.timestamp.claimed}`);
line(`Primary source       ${declaration.primarySource.url}`);
line(`Cited paragraph      ${declaration.citations[0].paragraph}`);
line(`Model                ${process.model.provider}/${process.model.name}@${process.model.version}`);
line(`Policy id            ${alignment.policy.id} v${alignment.policy.version}`);
line(`Human review needed  ${alignment.humanReviewRequired}`);
line();
line("Envelope saved to    " + envelopePath);
line("Tampered copy saved  " + out("envelope.tampered.json"));
line("Public key saved to  " + publicKeyPath);
line();
line("Next: run `node verify.mjs` to check both files.");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(buf)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
