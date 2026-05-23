/**
 * Example 2 — Verify the envelope produced by ./index.mjs.
 *
 * Reads ./envelope.json and ./envelope.tampered.json from disk, verifies
 * both against the public key in ./public-key.json, and prints a small
 * regulator-style report.
 *
 * This mirrors what an auditor or supervisory body would do when they are
 * given a TrustEnvelope and a public key: no LexiCo infrastructure, no
 * vendor API, no special tooling.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyLocal } from "@lexitsp/sdk/v3";

const here = dirname(fileURLToPath(import.meta.url));
const at = (name) => resolve(here, name);

const publicKey = JSON.parse(readFileSync(at("public-key.json"), "utf8"));

async function report(label, file) {
  const envelope = JSON.parse(readFileSync(at(file), "utf8"));
  const result = await verifyLocal(envelope, { knownPublicKey: publicKey });

  console.log(`\n${label} — ${file}`);
  console.log("-".repeat(50));
  const sigStatus = result.checks.signatures[0]?.status ?? "missing";
  console.log(`  valid              ${result.valid}`);
  console.log(`  schema             ${result.checks.schema.status}`);
  console.log(`  contentHash        ${result.checks.contentHash.status}`);
  console.log(`  ledgerHash         ${result.checks.ledgerHash.status}`);
  console.log(`  signature          ${sigStatus}`);
  if (!result.valid) {
    console.log("  ↳ this envelope should not be trusted.");
  }
  return result.valid;
}

const originalOk = await report("ORIGINAL", "envelope.json");
const tamperedOk = await report("TAMPERED", "envelope.tampered.json");

console.log();
if (originalOk && !tamperedOk) {
  console.log("✓ verifyLocal accepts the original and rejects the tampered copy.");
  console.log("  An auditor can run exactly this check, in any Node 18+ runtime,");
  console.log("  without contacting the issuing vendor.");
  process.exit(0);
} else {
  console.error("⚠ Unexpected verification result. Do not trust these envelopes.");
  process.exit(1);
}
