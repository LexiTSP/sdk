import { generateKeyPair, exportPublicKeyJwk, exportPrivateKeyJwk, importPrivateKeyJwk, sign as sigSign, type JwkEd25519Public } from "../crypto";
import { signInstanceCert } from "../manifest-sign";
import type { GeneratedRootKey } from "./generate-root";
import type { InstanceCertEntry } from "../manifest-types";

export interface IssueInstanceOptions {
  rootPackage: GeneratedRootKey;
  instanceId: string;
  validFrom: Date;
  validUntil: Date;
}

export interface IssuedInstance {
  id: string;
  cert: InstanceCertEntry;
  privateKeyJwk: JsonWebKey;
  publicKeyJwk: JwkEd25519Public;
}

export async function issueInstance(opts: IssueInstanceOptions): Promise<IssuedInstance> {
  const rootPriv = await importPrivateKeyJwk(opts.rootPackage.privateKeyJwk);
  const rootSigner = {
    sign: (data: Uint8Array) => sigSign(rootPriv, data),
    publicKey: opts.rootPackage.publicKeyJwk,
  };

  const instKp = await generateKeyPair();
  const instJwk = await exportPublicKeyJwk(instKp.publicKey);
  const instPrivJwk = await exportPrivateKeyJwk(instKp.privateKey);

  const cert = await signInstanceCert({
    rootSigner,
    payload: {
      id: opts.instanceId,
      publicKey: instJwk,
      validFrom: opts.validFrom.toISOString(),
      validUntil: opts.validUntil.toISOString(),
    },
  });

  return {
    id: opts.instanceId,
    cert,
    privateKeyJwk: instPrivJwk,
    publicKeyJwk: instJwk,
  };
}
