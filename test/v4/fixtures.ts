/**
 * Test fixtures for v4 (EXPERIMENTAL, RFC 0001 reference).
 */

import type {
  AiProvenance,
  AttestationProvenance,
  CredentialProvenance,
  Declaration,
  QA,
  SupplyChainProvenance,
} from "../../src/v4/types";

export const sampleDeclaration: Declaration = {
  primarySource: {
    type: "official-document",
    title: "BI Norwegian Business School transcript",
  },
  citations: [],
};

export const sampleQA: QA = {
  uncertainty: [],
  humanReviewRequired: false,
  policy: { id: "default", version: "1.0" },
};

export const sampleAiProvenance: AiProvenance = {
  kind: "ai",
  model: {
    name: "normistral",
    version: "11b-warm-3-2026q1",
    provider: "norwai-local",
    temperature: 0.0,
    contextWindow: 8192,
  },
  systemPrompt: {
    hash: "0".repeat(64),
    text: "You are a neutral translator. Translate only, recommend nothing.",
  },
};

export const sampleCredentialProvenance: CredentialProvenance = {
  kind: "credential",
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
};

export const sampleAttestationProvenance: AttestationProvenance = {
  kind: "attestation",
  attester: { id: "did:web:lexico.no", name: "LexiCo AS" },
  claim: {
    id: "system-uptime-2026-05-23",
    statement: "Operator confirms TSP risk-server reached steady state at 21:07Z.",
  },
  basis: { type: "observation", ref: "https://status.lexico.no/incidents/none" },
};

export const sampleSupplyChainProvenance: SupplyChainProvenance = {
  kind: "supply-chain",
  origin: { id: "factory-fsn1-batch-12", location: "Falkenstein, DE" },
  transformations: [
    {
      id: "transform-1",
      by: "did:web:supplier.example",
      at: "2026-05-22T08:00:00Z",
      inputs: [],
    },
  ],
};
