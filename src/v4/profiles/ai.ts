/**
 * @lexitsp/sdk v4 · profiles/ai — EXPERIMENTAL
 *
 * Helper for building `provenance: AiProvenance`. Semantically identical
 * to v3 Process; v3 → v4 migration for AI issuers is a pure rename.
 */

import type {
  AiProvenance,
  Model,
  PipelineStep,
  SystemPromptField,
} from "../types";

export interface AiProfileInput {
  model: Model;
  systemPrompt: SystemPromptField;
  pipeline?: PipelineStep[];
}

export function aiProfile(input: AiProfileInput): AiProvenance {
  return {
    kind: "ai",
    model: input.model,
    systemPrompt: input.systemPrompt,
    ...(input.pipeline !== undefined ? { pipeline: input.pipeline } : {}),
  };
}
