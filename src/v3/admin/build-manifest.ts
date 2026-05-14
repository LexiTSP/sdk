import { importPrivateKeyJwk, sign as sigSign } from "../crypto";
import { signManifest } from "../manifest-sign";
import { pruneRevoked } from "../revocation";
import type { GeneratedRootKey } from "./generate-root";
import type { IssuedInstance } from "./issue-instance";
import type { TrustManifest, RevokedEntry } from "../manifest-types";

export interface BuildManifestOptions {
  rootPackage: GeneratedRootKey;
  instances: IssuedInstance[];
  revoked?: RevokedEntry[];
  previousSequence?: number;
  acceptableAgeSeconds?: number;
  graceDays?: number;
}

export async function buildManifest(opts: BuildManifestOptions): Promise<TrustManifest> {
  const rootPriv = await importPrivateKeyJwk(opts.rootPackage.privateKeyJwk);
  const rootSigner = {
    sign: (data: Uint8Array) => sigSign(rootPriv, data),
    publicKey: opts.rootPackage.publicKeyJwk,
  };

  const sequence = (opts.previousSequence ?? 0) + 1;
  const acceptableAge = opts.acceptableAgeSeconds ?? 86400;
  const grace = opts.graceDays ?? 7;
  const issuedAt = new Date().toISOString();

  const prunedRevoked = pruneRevoked(opts.revoked ?? [], {
    now: issuedAt,
    acceptableAgeSeconds: acceptableAge,
    graceDays: grace,
  });

  return signManifest({
    rootSigner,
    organization: { name: opts.rootPackage.organization, domain: opts.rootPackage.domain },
    instances: opts.instances.map((i) => i.cert),
    revoked: prunedRevoked,
    sequence,
    issuedAt,
    acceptableAge: { seconds: acceptableAge },
  });
}
