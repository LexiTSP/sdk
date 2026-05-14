import { generateKeyPair, exportPublicKeyJwk, exportPrivateKeyJwk, type JwkEd25519Public } from "../crypto";

export interface GeneratedRootKey {
  organization: string;
  domain: string;
  privateKeyJwk: JsonWebKey;
  publicKeyJwk: JwkEd25519Public;
  createdAt: string;
}

export interface GenerateRootKeyOptions {
  organization: string;
  domain: string;
}

export async function generateRootKey(opts: GenerateRootKeyOptions): Promise<GeneratedRootKey> {
  const kp = await generateKeyPair();
  const privateKeyJwk = await exportPrivateKeyJwk(kp.privateKey);
  const publicKeyJwk = await exportPublicKeyJwk(kp.publicKey);
  return {
    organization: opts.organization,
    domain: opts.domain,
    privateKeyJwk,
    publicKeyJwk,
    createdAt: new Date().toISOString(),
  };
}
