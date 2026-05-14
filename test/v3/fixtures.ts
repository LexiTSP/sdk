import type {
  Declaration,
  Process,
  Alignment,
} from "../../src/v3/types";

export const sampleDeclaration: Declaration = {
  primarySource: {
    type: "legal-database",
    url: "https://lovdata.no/dokument/NL/lov/1997-02-28-19",
    title: "Folketrygdloven",
    retrieved: "2026-04-29T10:00:00Z",
  },
  citations: [
    {
      url: "https://lovdata.no/lov/1997-02-28-19/§11-5",
      paragraph: "§11-5",
      quote: "Det er et vilkår for rett til arbeidsavklaringspenger at...",
      retrieved: "2026-04-29T10:00:00Z",
    },
  ],
};

export const sampleProcess: Process = {
  model: {
    name: "normistral",
    version: "11b-warm-3-2026q1",
    provider: "norwai-local",
    temperature: 0.0,
    contextWindow: 8192,
  },
  systemPrompt: {
    hash: "0".repeat(64),
    text: "Du er en nøytral oversetter. Oversett kun, anbefal ingenting.",
  },
};

export const sampleAlignment: Alignment = {
  uncertainty: [],
  humanReviewRequired: false,
  policy: { id: "default", version: "1.0" },
};
