import {
  exportPrivateKeyJwk,
  exportPublicKeyJwk,
  generateKeyPair,
  importPrivateKeyJwk,
  pruneRevoked,
  sign,
  signInstanceCert,
  signManifest
} from "./chunk-CCJVYHGK.js";

// src/v3/admin/generate-root.ts
async function generateRootKey(opts) {
  const kp = await generateKeyPair();
  const privateKeyJwk = await exportPrivateKeyJwk(kp.privateKey);
  const publicKeyJwk = await exportPublicKeyJwk(kp.publicKey);
  return {
    organization: opts.organization,
    domain: opts.domain,
    privateKeyJwk,
    publicKeyJwk,
    createdAt: (/* @__PURE__ */ new Date()).toISOString()
  };
}

// src/v3/admin/issue-instance.ts
async function issueInstance(opts) {
  const rootPriv = await importPrivateKeyJwk(opts.rootPackage.privateKeyJwk);
  const rootSigner = {
    sign: (data) => sign(rootPriv, data),
    publicKey: opts.rootPackage.publicKeyJwk
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
      validUntil: opts.validUntil.toISOString()
    }
  });
  return {
    id: opts.instanceId,
    cert,
    privateKeyJwk: instPrivJwk,
    publicKeyJwk: instJwk
  };
}

// src/v3/admin/build-manifest.ts
async function buildManifest(opts) {
  const rootPriv = await importPrivateKeyJwk(opts.rootPackage.privateKeyJwk);
  const rootSigner = {
    sign: (data) => sign(rootPriv, data),
    publicKey: opts.rootPackage.publicKeyJwk
  };
  const sequence = (opts.previousSequence ?? 0) + 1;
  const acceptableAge = opts.acceptableAgeSeconds ?? 86400;
  const grace = opts.graceDays ?? 7;
  const issuedAt = (/* @__PURE__ */ new Date()).toISOString();
  const prunedRevoked = pruneRevoked(opts.revoked ?? [], {
    now: issuedAt,
    acceptableAgeSeconds: acceptableAge,
    graceDays: grace
  });
  return signManifest({
    rootSigner,
    organization: { name: opts.rootPackage.organization, domain: opts.rootPackage.domain },
    instances: opts.instances.map((i) => i.cert),
    revoked: prunedRevoked,
    sequence,
    issuedAt,
    acceptableAge: { seconds: acceptableAge }
  });
}

export {
  generateRootKey,
  issueInstance,
  buildManifest
};
