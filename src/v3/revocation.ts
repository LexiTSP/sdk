/**
 * @lexitsp/sdk v3 · revocation
 */

import type { RevokedEntry } from "./manifest-types";

export type RevocationResult =
  | { status: "not-revoked"; detail: string }
  | { status: "predates-revocation"; detail: string }
  | { status: "revoked"; detail: string };

export function checkRevocation(
  instanceId: string,
  envelopeTime: string,
  revoked: RevokedEntry[]
): RevocationResult {
  const entry = revoked.find((r) => r.id === instanceId);
  if (!entry) {
    return { status: "not-revoked", detail: `instance ${instanceId} not in revocation list` };
  }
  const envT = Date.parse(envelopeTime);
  const revT = Date.parse(entry.revokedAt);
  if (Number.isNaN(envT) || Number.isNaN(revT)) {
    return {
      status: "revoked",
      detail: `instance ${instanceId} revoked but timestamps unparseable; conservative reject`,
    };
  }
  if (envT < revT) {
    return {
      status: "predates-revocation",
      detail: `instance ${instanceId} revoked at ${entry.revokedAt} (reason: ${entry.reason}), envelope predates revocation`,
    };
  }
  return {
    status: "revoked",
    detail: `instance ${instanceId} revoked at ${entry.revokedAt} (reason: ${entry.reason})`,
  };
}

export interface PruneOptions {
  now: string;
  acceptableAgeSeconds: number;
  graceDays: number;
}

export function pruneRevoked(
  revoked: RevokedEntry[],
  opts: PruneOptions
): RevokedEntry[] {
  const nowMs = Date.parse(opts.now);
  const graceMs = opts.graceDays * 24 * 60 * 60 * 1000;
  const acceptableMs = opts.acceptableAgeSeconds * 1000;

  return revoked.filter((entry) => {
    const revMs = Date.parse(entry.revokedAt);
    if (Number.isNaN(revMs)) return true;
    const cutoff = revMs + acceptableMs + graceMs;
    return cutoff >= nowMs;
  });
}
