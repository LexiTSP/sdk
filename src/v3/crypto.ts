/**
 * Ed25519 primitives via Web Crypto API.
 *
 * Compatible with Node 18+, Bun 1+, modern browsers, and edge runtimes.
 * No external crypto dependencies.
 */

const ED25519_ALGORITHM = { name: "Ed25519" } as const;

export interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

export interface JwkEd25519Public {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  alg?: "EdDSA";
  use?: "sig";
  kid?: string;
}

export async function generateKeyPair(): Promise<KeyPair> {
  const kp = (await crypto.subtle.generateKey(
    ED25519_ALGORITHM,
    true,
    ["sign", "verify"]
  )) as CryptoKeyPair;
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export async function sign(
  privateKey: CryptoKey,
  data: Uint8Array
): Promise<Uint8Array> {
  const buf = await crypto.subtle.sign(ED25519_ALGORITHM, privateKey, data as BufferSource);
  return new Uint8Array(buf);
}

export async function verify(
  publicKey: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array
): Promise<boolean> {
  return crypto.subtle.verify(ED25519_ALGORITHM, publicKey, signature as BufferSource, data as BufferSource);
}

export async function exportPublicKeyJwk(
  publicKey: CryptoKey
): Promise<JwkEd25519Public> {
  const jwk = (await crypto.subtle.exportKey("jwk", publicKey)) as JwkEd25519Public;
  return jwk;
}

export async function importPublicKeyJwk(
  jwk: JwkEd25519Public
): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk, ED25519_ALGORITHM, true, ["verify"]);
}

export async function importPrivateKeyJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk, ED25519_ALGORITHM, true, ["sign"]);
}

export async function exportPrivateKeyJwk(
  privateKey: CryptoKey
): Promise<JsonWebKey> {
  return crypto.subtle.exportKey("jwk", privateKey);
}
