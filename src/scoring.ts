/**
 * @lexitsp/sdk · scoring
 *
 * Deterministic confidence-score computation per TSP spec v2.0.
 *
 * Score = scoreSource × 0.5 + scoreProcess × 0.3 + scoreAlignment × 0.2
 *
 * Every implementation produces the same score for the same inputs.
 * This reproducibility is what makes the score auditable.
 */

import type {
  Alignment,
  ConfidenceLevel,
  Process,
  Source,
  SourceType,
} from "./types";

export const WEIGHTS = { source: 0.5, process: 0.3, alignment: 0.2 } as const;

export const SOURCE_TYPE_SCORES: Record<SourceType, number> = {
  "legal-database": 1.0,
  "government-website": 0.95,
  "official-document": 0.9,
  "academic-paper": 0.85,
  "verified-website": 0.7,
  "model-knowledge": 0.6,
  "user-input": 0.5,
  unknown: 0.3,
};

const TRANSPARENT_PIPELINES = new Set([
  "RAG",
  "RAG + Legal Fine-tuning",
  "RAG + Legal",
  "Fine-tuned",
  "Prompt-engineered",
  "Structured Output",
  "Chain-of-thought",
]);

export function scoreSource(s: Source): number {
  const typeScore = SOURCE_TYPE_SCORES[s.type] ?? 0.3;
  const conf = Math.max(0, Math.min(1, s.confidence));
  const raw = typeScore * conf;
  const citationBonus = Math.min(0.1, (s.citations?.length ?? 0) * 0.02);
  return Math.min(1, raw + citationBonus);
}

export function scoreProcess(p: Process): number {
  let score = 0.5;
  if (TRANSPARENT_PIPELINES.has(p.pipeline)) score += 0.2;
  if ((p.steps?.length ?? 0) >= 2) score += 0.15;
  if (p.parameters && Object.keys(p.parameters).length > 0) score += 0.1;
  if (p.durationMs !== undefined) score += 0.05;
  return Math.min(1, score);
}

export function scoreAlignment(a: Alignment): number {
  let score = 1.0;
  score -= a.riskLevel * 0.15;
  if (!a.ethicsCheck) score -= 0.3;
  score -= Math.max(0, Math.min(1, a.biasScore)) * 0.2;
  if (a.flags?.length) score -= Math.min(0.3, a.flags.length * 0.05);
  if (a.humanReviewRequired) score -= 0.15;
  return Math.max(0, Math.min(1, score));
}

export function computeConfidenceScore(
  s: Source,
  p: Process,
  a: Alignment,
): number {
  const x =
    scoreSource(s) * WEIGHTS.source +
    scoreProcess(p) * WEIGHTS.process +
    scoreAlignment(a) * WEIGHTS.alignment;
  return Math.round(x * 100);
}

export function classifyLevel(score: number): ConfidenceLevel {
  if (score >= 90) return "high";
  if (score >= 70) return "medium";
  if (score >= 50) return "low";
  return "critical";
}
