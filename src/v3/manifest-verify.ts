/**
 * @lexitsp/sdk v3 · manifest verification
 */

import { canonicalize } from "./canonical";
import { importPublicKeyJwk, verify as verifyEd25519, type JwkEd25519Public } from "./crypto";
import type { TrustManifest, InstanceCertEntry } from "./manifest-types";

const enc = new TextEncoder();

function base64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

export async function verifyManifestSignature(
  manifest: TrustManifest
): Promise<boolean> {
  const { rootSignatureOverManifest, ...unsigned } = manifest;
  let pubKey;
  let sigBytes;
  try {
    pubKey = await importPublicKeyJwk(manifest.rootKey);
    sigBytes = base64ToBytes(rootSignatureOverManifest);
  } catch {
    return false;
  }
  try {
    return await verifyEd25519(pubKey, sigBytes, enc.encode(canonicalize(unsigned)));
  } catch {
    return false;
  }
}

export async function verifyInstanceCert(
  cert: InstanceCertEntry,
  rootKey: JwkEd25519Public
): Promise<boolean> {
  const { rootSignature, ...payload } = cert;
  let pubKey;
  let sigBytes;
  try {
    pubKey = await importPublicKeyJwk(rootKey);
    sigBytes = base64ToBytes(rootSignature);
  } catch {
    return false;
  }
  try {
    return await verifyEd25519(pubKey, sigBytes, enc.encode(canonicalize(payload)));
  } catch {
    return false;
  }
}
