import { J as JwkEd25519Public, a as InstanceCertEntry, R as RevokedEntry, c as TrustManifest } from '../../manifest-types-BvltqKuH.js';

interface GeneratedRootKey {
    organization: string;
    domain: string;
    privateKeyJwk: JsonWebKey;
    publicKeyJwk: JwkEd25519Public;
    createdAt: string;
}
interface GenerateRootKeyOptions {
    organization: string;
    domain: string;
}
declare function generateRootKey(opts: GenerateRootKeyOptions): Promise<GeneratedRootKey>;

interface IssueInstanceOptions {
    rootPackage: GeneratedRootKey;
    instanceId: string;
    validFrom: Date;
    validUntil: Date;
}
interface IssuedInstance {
    id: string;
    cert: InstanceCertEntry;
    privateKeyJwk: JsonWebKey;
    publicKeyJwk: JwkEd25519Public;
}
declare function issueInstance(opts: IssueInstanceOptions): Promise<IssuedInstance>;

interface BuildManifestOptions {
    rootPackage: GeneratedRootKey;
    instances: IssuedInstance[];
    revoked?: RevokedEntry[];
    previousSequence?: number;
    acceptableAgeSeconds?: number;
    graceDays?: number;
}
declare function buildManifest(opts: BuildManifestOptions): Promise<TrustManifest>;

export { type BuildManifestOptions, type GenerateRootKeyOptions, type GeneratedRootKey, type IssueInstanceOptions, type IssuedInstance, buildManifest, generateRootKey, issueInstance };
