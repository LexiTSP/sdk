/**
 * @lexitsp/sdk v3 · manifest types
 *
 * TrustManifest is the well-known artifact that maps an organization
 * to its rooted key infrastructure. It is signed by the org-root and
 * contains the active instance certificates plus a revocation list.
 */

import type { JwkEd25519Public } from "./crypto";
import type { Base64, ISO8601 } from "./types";

export interface InstanceCertEntry {
  id: string;
  publicKey: JwkEd25519Public;
  validFrom: ISO8601;
  validUntil: ISO8601;
  rootSignature: Base64;
}

export interface RevokedEntry {
  id: string;
  revokedAt: ISO8601;
  reason: string;
}

export interface AcceptableAge {
  seconds: number;
}

export interface TrustManifest {
  tsp: "3.0";
  organization: {
    name: string;
    domain: string;
  };
  rootKey: JwkEd25519Public;
  instances: InstanceCertEntry[];
  revoked: RevokedEntry[];
  sequence: number;
  issuedAt: ISO8601;
  acceptableAge: AcceptableAge;
  rootSignatureOverManifest: Base64;
}

export type UnsignedManifest = Omit<TrustManifest, "rootSignatureOverManifest">;
export type InstanceCertPayload = Omit<InstanceCertEntry, "rootSignature">;
