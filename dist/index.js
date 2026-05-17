// src/envelope.ts
import { nanoid } from "nanoid";

// src/crypto.ts
var encoder = new TextEncoder();
async function sha256(input) {
  const buf = await crypto.subtle.digest("SHA-256", encoder.encode(input));
  const bytes = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}
function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const obj = value;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k])).join(",") + "}";
}

// src/scoring.ts
var WEIGHTS = { source: 0.5, process: 0.3, alignment: 0.2 };
var SOURCE_TYPE_SCORES = {
  "legal-database": 1,
  "government-website": 0.95,
  "official-document": 0.9,
  "academic-paper": 0.85,
  "verified-website": 0.7,
  "model-knowledge": 0.6,
  "user-input": 0.5,
  unknown: 0.3
};
var TRANSPARENT_PIPELINES = /* @__PURE__ */ new Set([
  "RAG",
  "RAG + Legal Fine-tuning",
  "RAG + Legal",
  "Fine-tuned",
  "Prompt-engineered",
  "Structured Output",
  "Chain-of-thought"
]);
function scoreSource(s) {
  const typeScore = SOURCE_TYPE_SCORES[s.type] ?? 0.3;
  const conf = Math.max(0, Math.min(1, s.confidence));
  const raw = typeScore * conf;
  const citationBonus = Math.min(0.1, (s.citations?.length ?? 0) * 0.02);
  return Math.min(1, raw + citationBonus);
}
function scoreProcess(p) {
  let score = 0.5;
  if (TRANSPARENT_PIPELINES.has(p.pipeline)) score += 0.2;
  if ((p.steps?.length ?? 0) >= 2) score += 0.15;
  if (p.parameters && Object.keys(p.parameters).length > 0) score += 0.1;
  if (p.durationMs !== void 0) score += 0.05;
  return Math.min(1, score);
}
function scoreAlignment(a) {
  let score = 1;
  score -= a.riskLevel * 0.15;
  if (!a.ethicsCheck) score -= 0.3;
  score -= Math.max(0, Math.min(1, a.biasScore)) * 0.2;
  if (a.flags?.length) score -= Math.min(0.3, a.flags.length * 0.05);
  if (a.humanReviewRequired) score -= 0.15;
  return Math.max(0, Math.min(1, score));
}
function computeConfidenceScore(s, p, a) {
  const x = scoreSource(s) * WEIGHTS.source + scoreProcess(p) * WEIGHTS.process + scoreAlignment(a) * WEIGHTS.alignment;
  return Math.round(x * 100);
}
function classifyLevel(score) {
  if (score >= 90) return "high";
  if (score >= 70) return "medium";
  if (score >= 50) return "low";
  return "critical";
}

// src/envelope.ts
var TSP_VERSION = "2.0.0";
async function wrap(content, config, options = {}) {
  const now = options.timestamp ?? (/* @__PURE__ */ new Date()).toISOString();
  const source = {
    ...config.source,
    accessedAt: config.source.accessedAt ?? now
  };
  const process = {
    ...config.process,
    timestamp: config.process.timestamp ?? now
  };
  const alignment = config.alignment;
  const confidenceScore = computeConfidenceScore(source, process, alignment);
  const confidenceLevel = classifyLevel(confidenceScore);
  const id = options.id ?? `tsp_${nanoid(16)}`;
  const hashable = canonicalJson({
    version: TSP_VERSION,
    id,
    content,
    source,
    process,
    alignment,
    previousHash: options.previousHash ?? null
  });
  const hash = await sha256(hashable);
  const ledger = {
    id,
    hash,
    timestamp: now,
    previousHash: options.previousHash,
    blockHeight: options.blockHeight
  };
  return {
    version: TSP_VERSION,
    content,
    confidenceScore,
    confidenceLevel,
    source,
    process,
    alignment,
    ledger
  };
}
function toJsonLd(envelope) {
  return {
    "@context": "https://truststandardprotocol.com/context/v2",
    "@type": "TrustEnvelope",
    "@id": envelope.ledger.id,
    version: envelope.version,
    content: envelope.content,
    confidence: {
      score: envelope.confidenceScore,
      level: envelope.confidenceLevel
    },
    source: envelope.source,
    process: envelope.process,
    alignment: envelope.alignment,
    ledger: envelope.ledger
  };
}

// src/verify.ts
async function verify(envelope) {
  const errors = [];
  const hashable = canonicalJson({
    version: envelope.version,
    id: envelope.ledger.id,
    content: envelope.content,
    source: envelope.source,
    process: envelope.process,
    alignment: envelope.alignment,
    previousHash: envelope.ledger.previousHash ?? null
  });
  const expectedHash = await sha256(hashable);
  const hashValid = expectedHash === envelope.ledger.hash;
  if (!hashValid) {
    errors.push(
      `Hash mismatch: expected ${expectedHash.slice(0, 12)}..., got ${envelope.ledger.hash.slice(0, 12)}...`
    );
  }
  const expectedScore = computeConfidenceScore(
    envelope.source,
    envelope.process,
    envelope.alignment
  );
  const scoreValid = expectedScore === envelope.confidenceScore;
  if (!scoreValid) {
    errors.push(
      `Score mismatch: expected ${expectedScore}, got ${envelope.confidenceScore}`
    );
  }
  return {
    valid: hashValid && scoreValid,
    hashValid,
    scoreValid,
    errors
  };
}
async function verifyChain(envelopes) {
  const errors = [];
  for (let i = 0; i < envelopes.length; i++) {
    const e = envelopes[i];
    const single = await verify(e);
    if (!single.valid) {
      return {
        valid: false,
        totalEnvelopes: envelopes.length,
        brokenAt: i,
        reason: single.errors[0] ?? "envelope invalid",
        errors: single.errors
      };
    }
    if (i > 0) {
      const prev = envelopes[i - 1];
      if (e.ledger.previousHash !== prev.ledger.hash) {
        const reason = `chain link broken at index ${i}: previousHash ${e.ledger.previousHash?.slice(0, 12) ?? "(none)"}... does not match prior hash ${prev.ledger.hash.slice(0, 12)}...`;
        errors.push(reason);
        return {
          valid: false,
          totalEnvelopes: envelopes.length,
          brokenAt: i,
          reason,
          errors
        };
      }
    }
  }
  return {
    valid: true,
    totalEnvelopes: envelopes.length,
    errors: []
  };
}

// src/index.ts
var tsp = {
  version: TSP_VERSION,
  wrap,
  verify,
  verifyChain,
  toJsonLd
};
export {
  SOURCE_TYPE_SCORES,
  TSP_VERSION,
  WEIGHTS,
  canonicalJson,
  classifyLevel,
  computeConfidenceScore,
  scoreAlignment,
  scoreProcess,
  scoreSource,
  sha256,
  toJsonLd,
  tsp,
  verify,
  verifyChain,
  wrap
};
