/**
 * @lexitsp/sdk v3 · manifest signing
 */

import { canonicalize } from "./canonical";
import type { JwkEd25519Public } from "./crypto";
import type {
  InstanceCertEntry,
  InstanceCertPayload,
  RevokedEntry,
  TrustManifest,
  AcceptableAge,
  UnsignedManifest,
} from "./manifest-types";

const enc = new TextEncoder();

export interface RootSigner {
  sign(data: Uint8Array): Promise<Uint8Array>;
  publicKey: JwkEd25519Public;
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export interface InstanceCertSignInput {
  rootSigner: RootSigner;
  payload: InstanceCertPayload;
}

export async function signInstanceCert(
  input: InstanceCertSignInput
): Promise<InstanceCertEntry> {
  const sigBytes = await input.rootSigner.sign(
    enc.encode(canonicalize(input.payload))
  );
  return {
    ...input.payload,
    rootSignature: bytesToBase64(sigBytes),
  };
}

export interface ManifestSignInput {
  rootSigner: RootSigner;
  organization: { name: string; domain: string };
  instances: InstanceCertEntry[];
  revoked: RevokedEntry[];
  sequence: number;
  issuedAt: string;
  acceptableAge: AcceptableAge;
}

export async function signManifest(
  input: ManifestSignInput
): Promise<TrustManifest> {
  const unsigned: UnsignedManifest = {
    tsp: "3.0",
    organization: input.organization,
    rootKey: input.rootSigner.publicKey,
    instances: input.instances,
    revoked: input.revoked,
    sequence: input.sequence,
    issuedAt: input.issuedAt,
    acceptableAge: input.acceptableAge,
  };

  const sigBytes = await input.rootSigner.sign(enc.encode(canonicalize(unsigned)));

  return {
    ...unsigned,
    rootSignatureOverManifest: bytesToBase64(sigBytes),
  };
}
