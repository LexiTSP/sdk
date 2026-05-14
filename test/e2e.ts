/**
 * SDK end-to-end smoke test.
 *
 * Run with:  bun run packages/lexitsp-sdk/test/e2e.ts
 *
 * Verifies that:
 *  1. wrap() produces a valid envelope
 *  2. verify() confirms the envelope
 *  3. canonicalJson is deterministic across calls
 *  4. Hash chain links correctly across multiple envelopes
 *  5. FileLedger persists and re-reads identically
 *  6. verifyChain detects broken links
 */

import { tsp, computeConfidenceScore } from "../src/index";
import { FileLedger } from "../src/node/index";
import fs from "node:fs/promises";

const TEST_LEDGER = "./test-ledger.jsonl";

async function cleanup() {
  await fs.rm(TEST_LEDGER, { force: true });
}

function assert(cond: boolean, msg: string) {
  if (!cond) {
    console.error(`\u2717 ${msg}`);
    process.exit(1);
  }
  console.log(`\u2713 ${msg}`);
}

async function main() {
  await cleanup();

  console.log("\n=== Test 1: wrap() produces valid envelope ===");
  const env1 = await tsp.wrap("Du har rett på AAP fordi diagnosen er kronisk.", {
    source: {
      name: "Lovdata",
      type: "legal-database",
      confidence: 0.95,
      citations: [{ text: "Ftrl. § 11-5", url: "https://lovdata.no/ftrl/11-5" }],
    },
    process: {
      model: "gpt-4o",
      pipeline: "RAG + Legal",
      steps: ["retrieve", "rank", "generate"],
      durationMs: 142,
    },
    alignment: {
      riskLevel: 1,
      ethicsCheck: true,
      biasScore: 0.05,
      domain: "welfare",
    },
  });
  assert(env1.confidenceScore > 0 && env1.confidenceScore <= 100, `confidenceScore in range: ${env1.confidenceScore}`);
  assert(env1.confidenceLevel === "high", `confidenceLevel high (got ${env1.confidenceLevel})`);
  assert(env1.ledger.hash.length === 64, `hash is 64 hex chars`);
  assert(env1.ledger.previousHash === undefined, `first envelope has no previousHash`);

  console.log("\n=== Test 2: verify() confirms the envelope ===");
  const verify1 = await tsp.verify(env1);
  assert(verify1.valid, `envelope verifies as valid`);
  assert(verify1.hashValid, `hash valid`);
  assert(verify1.scoreValid, `score valid`);

  console.log("\n=== Test 3: deterministic scoring ===");
  const score1 = computeConfidenceScore(env1.source, env1.process, env1.alignment);
  const score2 = computeConfidenceScore(env1.source, env1.process, env1.alignment);
  assert(score1 === score2, `score reproducible: ${score1}`);
  assert(score1 === env1.confidenceScore, `score matches envelope`);

  console.log("\n=== Test 4: hash chain links correctly ===");
  const env2 = await tsp.wrap("Svarsannsynlighet ca 60 dager.", {
    source: { name: "NAV.no", type: "government-website", confidence: 0.9 },
    process: { model: "gpt-4o", pipeline: "RAG", steps: ["lookup", "generate"] },
    alignment: { riskLevel: 1, ethicsCheck: true, biasScore: 0.05, domain: "welfare" },
  }, { previousHash: env1.ledger.hash });
  assert(env2.ledger.previousHash === env1.ledger.hash, `chain link set correctly`);

  console.log("\n=== Test 5: FileLedger persistence ===");
  const ledger = new FileLedger(TEST_LEDGER);
  await ledger.save(env1);
  await ledger.save(env2);
  assert((await ledger.count()) === 2, `count is 2 after two saves`);

  const ledger2 = new FileLedger(TEST_LEDGER);
  const all = await ledger2.all();
  assert(all.length === 2, `re-read finds 2 envelopes`);
  assert(all[0].ledger.id === env1.ledger.id, `first envelope id matches`);
  assert(all[1].ledger.previousHash === all[0].ledger.hash, `chain preserved on disk`);

  console.log("\n=== Test 6: verifyChain detects broken links ===");
  const goodChain = await tsp.verifyChain([env1, env2]);
  assert(goodChain.valid, `intact chain verifies`);
  assert(goodChain.totalEnvelopes === 2, `total envelopes correct`);

  const tamperedEnv2 = { ...env2, content: "MALICIOUSLY ALTERED" };
  const tamperedChain = await tsp.verifyChain([env1, tamperedEnv2]);
  assert(!tamperedChain.valid, `tampered chain detected`);
  assert(tamperedChain.brokenAt === 1, `break detected at index 1`);

  const env3 = await tsp.wrap("...", {
    source: { name: "x", type: "unknown", confidence: 0.5 },
    process: { model: "x", pipeline: "x", steps: ["x"] },
    alignment: { riskLevel: 0, ethicsCheck: true, biasScore: 0.1 },
  }, { previousHash: "deadbeef" });
  const brokenLink = await tsp.verifyChain([env1, env3]);
  assert(!brokenLink.valid, `broken chain link detected`);

  console.log("\n=== Test 7: stats aggregation ===");
  const stats = await ledger2.stats();
  assert(stats.totalInteractions === 2, `total interactions = 2`);
  assert(stats.averageConfidence > 0, `avg confidence calculated`);
  assert(stats.confidenceLevelCounts.high >= 1, `high count >= 1`);
  assert(stats.lastHash === env2.ledger.hash, `lastHash = env2.hash`);

  console.log("\n=== All tests passed ===\n");

  await cleanup();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
