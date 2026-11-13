// did:webvh key resolution for zcap verification. An account registered as
// a did:webvh is controlled by whichever keys its log's current document
// lists: a request signed by <did:webvh>#<multibase> verifies when that
// method is listed under capabilityInvocation (the current-key-set rule the
// PWS server applies). The log is fetched over HTTPS from the identity
// domain the DID names, with a timeout and a size cap, and cached briefly.
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

const isLogUrl = (url) => String(url).endsWith("/did.jsonl");

// By DID: the resolved document, the ETag of the log it came from, and
// when the document is next validated
const cache = new Map();

// A document is kept for CACHE_MS and then validated, not discarded: the
// log is fetched conditionally against the ETag the document came from,
// and an unchanged log (a 304) keeps the document, and the walk of the log
// it cost, for another lifetime. An account log grows with every client
// and credential, so it is downloaded and walked again only when it
// changed, which is also what `fresh` (a key the cached document does not
// list) needs: an unchanged log lists no new key either. `now` is for tests.
export async function resolveWebvhDocument(did, { fresh = false, now = Date.now } = {}) {
  const cached = cache.get(did);
  if (cached && cached.expires > now() && !fresh) {
    return cached.doc;
  }
  let etag;
  let notModified = false;
  const fetchImpl = async (url, init = {}) => {
    const conditional = isLogUrl(url) && cached?.etag !== undefined;
    const response = await limitedFetch(url, conditional ? { ...init, headers: { ...(init.headers ?? {}), "if-none-match": cached.etag } } : init);
    if (conditional && response.status === 304) {
      notModified = true;
      // The driver stops here; the document it would walk to is the one cached
      throw new Error("not modified");
    }
    if (isLogUrl(url)) {
      etag = response.headers?.get?.("etag") ?? undefined;
    }
    return response;
  };
  let result;
  try {
    result = await webvh.resolveDID(did, { fetch: fetchImpl });
  } catch (err) {
    if (!notModified) {
      throw err;
    }
  }
  if (notModified) {
    cached.expires = now() + CACHE_MS;
    return cached.doc;
  }
  if (!result.didDocument) {
    throw new Error(`${did} does not resolve: ${result.didResolutionMetadata?.error ?? "no document"}.`);
  }
  if (result.didDocumentMetadata?.deactivated) {
    throw new Error(`${did} is deactivated.`);
  }
  const doc = absoluteIds(result.didDocument);
  cache.set(did, { doc, etag, expires: now() + CACHE_MS });
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
  let doc = await resolveWebvhDocument(did);
  if (fragment === undefined) {
    return doc;
  }
  const lookup = (d) => {
    const listed = relationIds(d, "capabilityInvocation").includes(id) || relationIds(d, "capabilityDelegation").includes(id);
    const found = (d.verificationMethod ?? []).find((entry) => entry?.id === id);
    return listed ? found : undefined;
  };
  // A key the cached document does not list is looked up once more against a
  // fresh resolution: a credential added a moment ago must work at once,
  // while a removed key keeps working only until the cache expires.
  let method = lookup(doc);
  if (!method) {
    doc = await resolveWebvhDocument(did, { fresh: true });
    method = lookup(doc);
  }
  if (!method?.publicKeyMultibase) {
    throw new Error(`${id} is not a capability key of ${did}.`);
  }
  return { "@context": "https://w3id.org/security/multikey/v1", ...method, type: "Multikey", controller: method.controller ?? did };
}

const didResolver = createDefaultDidResolver();
// did:webvh documents are cached (and refreshed on a missing key) above; the
// resolver's own memo would only serve the controller document stale.
didResolver._cache = { memoize: ({ fn }) => fn() };
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
