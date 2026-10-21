// did:webvh key resolution for zcap verification. An account registered as
// a did:webvh is controlled by whichever keys its log's current document
// lists: a request signed by <did:webvh>#<multibase> verifies when that
// method is listed under capabilityInvocation (the current-key-set rule the
// PWS server applies). The log is fetched over HTTPS from the identity
// domain the DID names, with a timeout and a size cap, and cached briefly.
// Kept in this function's own directory because SAM's esbuild build only
// packages files under the function's CodeUri.
import * as webvh from "@interop/did-method-webvh";
import { Ed25519VerificationKey } from "@interop/ed25519-verification-key";
import { securityLoader, createDefaultDidResolver } from "@interop/security-document-loader";

const CACHE_MS = Number(process.env.WEBVH_CACHE_SECONDS ?? "30") * 1000;
const FETCH_TIMEOUT_MS = Number(process.env.WEBVH_FETCH_TIMEOUT_MS ?? "3000");
const MAX_LOG_BYTES = Number(process.env.WEBVH_MAX_LOG_BYTES ?? String(1024 * 1024));
const RELATIONS = ["authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"];

export const isWebvhDid = (id) => typeof id === "string" && id.startsWith("did:webvh:");

// The document writes relationship entries as `#fragment`; the zcap library
// compares them to the signing key's absolute id.
function absoluteIds(doc) {
  const absolute = (id) => (typeof id === "string" && id.startsWith("#") ? `${doc.id}${id}` : id);
  const out = { ...doc };
  for (const relation of RELATIONS) {
    if (Array.isArray(doc[relation])) {
      out[relation] = doc[relation].map((entry) =>
        typeof entry === "string" ? absolute(entry) : { ...entry, id: absolute(entry?.id) }
      );
    }
  }
  if (Array.isArray(doc.verificationMethod)) {
    out.verificationMethod = doc.verificationMethod.map((method) => ({ ...method, id: absolute(method?.id) }));
  }
  return out;
}

// A fetch with the limits applied, in the shape the driver accepts.
async function limitedFetch(url, init = {}) {
  const response = await globalThis.fetch(url, { ...init, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  const length = Number(response.headers?.get?.("content-length") ?? 0);
  if (length > MAX_LOG_BYTES) {
    throw new Error(`DID log at ${url} exceeds ${MAX_LOG_BYTES} bytes.`);
  }
  return response;
}

const cache = new Map();

export async function resolveWebvhDocument(did) {
  const cached = cache.get(did);
  if (cached && cached.expires > Date.now()) {
    return cached.doc;
  }
  const result = await webvh.resolveDID(did, { fetch: limitedFetch });
  if (!result.didDocument) {
    throw new Error(`${did} does not resolve: ${result.didResolutionMetadata?.error ?? "no document"}.`);
  }
  if (result.didDocumentMetadata?.deactivated) {
    throw new Error(`${did} is deactivated.`);
  }
  const doc = absoluteIds(result.didDocument);
  cache.set(did, { doc, expires: Date.now() + CACHE_MS });
  return doc;
}

export function clearWebvhCache() {
  cache.clear();
}

function relationIds(doc, relation) {
  return (doc[relation] ?? []).map((entry) => (typeof entry === "string" ? entry : entry?.id)).filter(Boolean);
}

// The document, or the one verification method a key URL names, which must
// be listed under capabilityInvocation (or capabilityDelegation, for a
// delegation's proof).
async function resolveWebvh(id) {
  const [did, fragment] = id.split("#");
  const doc = await resolveWebvhDocument(did);
  if (fragment === undefined) {
    return doc;
  }
  const listed = relationIds(doc, "capabilityInvocation").includes(id) || relationIds(doc, "capabilityDelegation").includes(id);
  const method = (doc.verificationMethod ?? []).find((entry) => entry?.id === id);
  if (!listed || !method?.publicKeyMultibase) {
    throw new Error(`${id} is not a capability key of ${did}.`);
  }
  return { "@context": "https://w3id.org/security/multikey/v1", ...method, type: "Multikey", controller: method.controller ?? did };
}

const didResolver = createDefaultDidResolver();
didResolver.use({ method: "webvh", get: ({ did, url }) => resolveWebvh(did ?? url) });

// The document loader zcap verification runs with: did:key, did:web and
// did:webvh.
export const documentLoader = securityLoader({ didResolver }).build();

// The verifier for a signing key id: a did:webvh method from the resolved
// document, or a did:key through the loader.
export async function getVerifier({ keyId }) {
  if (isWebvhDid(keyId)) {
    const verificationMethod = await resolveWebvh(keyId);
    const key = await Ed25519VerificationKey.from(verificationMethod);
    return { verifier: key.verifier(), verificationMethod };
  }
  const { document } = await documentLoader(keyId);
  const key = await Ed25519VerificationKey.fromKeyDocument({ document });
  return { verifier: key.verifier(), verificationMethod: document };
}
