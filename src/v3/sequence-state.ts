/**
 * @lexitsp/sdk v3 · sequence state
 *
 * Tracks the highest-sequence manifest seen per organization domain
 * to detect rollback attacks.
 */

const highestSeen = new Map<string, number>();

export function clearSequenceState(): void {
  highestSeen.clear();
}

export interface SequenceCheckResult {
  rollback: boolean;
  highestSeen: number | null;
  received: number;
}

export function checkSequence(domain: string, sequence: number): SequenceCheckResult {
  const prior = highestSeen.get(domain) ?? null;
  if (prior !== null && sequence < prior) {
    return { rollback: true, highestSeen: prior, received: sequence };
  }
  return { rollback: false, highestSeen: prior, received: sequence };
}

export function recordSequence(domain: string, sequence: number): void {
  const prior = highestSeen.get(domain);
  if (prior === undefined || sequence > prior) {
    highestSeen.set(domain, sequence);
  }
}
