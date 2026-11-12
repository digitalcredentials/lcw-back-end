// zCap invocation verification against an account's registered DID, shared
// by every function that authenticates a wallet session (lcw-login,
// lcw-recovery, and batch-issuer-backend's notify) through the webvh-verify
// Lambda layer. The invoked root capability is controlled by the DID
// registered for the email, so verification itself rejects invocations
// signed by anyone else's key; a registered did:webvh is controlled by the
// keys its log's current document lists (webvh.mjs).
//
// Always used bundled (`npm run build` -> dist/index.mjs), by the layer and
// by the functions' local tests alike: loaded from node_modules unbundled,
// the CJS/ESM cycle between @interop/jsonld-signatures and
// @interop/data-integrity-core fails at load.
//
// http-client first: @interop/jsonld (CJS) require()s this ESM package
// mid-graph and hits a TDZ error when it is not already evaluated.
import "@interop/http-client";
import { verifyCapabilityInvocation } from "@interop/http-signature-zcap-verify";
import { Ed25519Signature2020 } from "@interop/ed25519-signature";
import { createRootCapability } from "@interop/zcap";
import { documentLoader, getVerifier, isWebvhDid, resolveWebvhDocument } from "./webvh.mjs";

export { documentLoader, getVerifier, resolveWebvhDocument, clearWebvhCache, isWebvhDid } from "./webvh.mjs";

// The service type under which an account document names its client-annex
// DID (wallet-core's delegated-clients pointer): the did:webvh whose
// document lists the keys of the account's transient wallet sessions.
const DELEGATED_CLIENTS_SERVICE_TYPE = "https://w3id.org/byoe#DelegatedClients";

// The DID a request's HTTP signature names (the keyId without its fragment).
function signerDidOf(headers) {
    const keyId = headers.authorization?.match(/keyId="([^"]+)"/)?.[1];
    return keyId?.split("#")[0];
}

// The client-annex DID the registered account's current document points at,
// or undefined when it names none (or is not a did:webvh). `fresh` bypasses
// the resolver's cache.
async function clientAnnexDidOf(registeredDid, { fresh = false } = {}) {
    if (!isWebvhDid(registeredDid)) {
        return undefined;
    }
    const doc = await resolveWebvhDocument(registeredDid, { fresh });
    const entry = (doc.service ?? []).find((service) => [service?.type].flat().includes(DELEGATED_CLIENTS_SERVICE_TYPE));
    return typeof entry?.serviceEndpoint === "string" ? entry.serviceEndpoint : undefined;
}

// True when `event` (an HTTP API payload v2 event) carries a zcap invocation
// of its own URL signed by `registeredDid`, or by the client-annex DID the
// registered account's document points at. A wallet session opened with a
// password is a transient client of the account's annex: its key is listed
// in the annex document, under capabilityInvocation, not in the account
// document, and the annex DID is what the account names as its delegated
// clients. A session opened with a passkey is an enrolled client whose key
// the account document itself lists. The URL is rebuilt from the request's
// proto/host/path, so signatures verify under sam local as well as behind
// API Gateway, and includes the query string, so signed query parameters
// (email, space) cannot be swapped. Header names are lowercased first: API
// Gateway delivers them lowercase, sam local preserves casing.
export async function verifyAccountInvocation({ event, registeredDid }) {
    const headers = Object.fromEntries(
        Object.entries(event.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value])
    );
    const proto = headers["x-forwarded-proto"] ?? "https";
    const host = headers.host ?? event.requestContext.domainName;
    const query = event.rawQueryString ? `?${event.rawQueryString}` : "";
    const url = `${proto}://${host}${event.rawPath}${query}`;
    const method = event.requestContext.http.method;
    // The root capability's controller: the registered DID, or the annex
    // DID when that is what signed and the account points at it.
    let controller = registeredDid;
    const signer = signerDidOf(headers);
    if (signer && signer !== registeredDid && isWebvhDid(signer)) {
        const annexOf = (options) =>
            clientAnnexDidOf(registeredDid, options).catch((error) => {
                console.error("Could not read the account's delegated-clients pointer:", error);
                return undefined;
            });
        let annex = await annexOf();
        if (annex !== signer) {
            // The cached document may be behind the log: a recovery login
            // mints a fresh annex generation, re-points the account at it
            // and signs in under it in the same second. One fresh
            // resolution before refusing, as a key the cached document does
            // not list gets.
            annex = await annexOf({ fresh: true });
        }
        if (annex === signer) {
            controller = annex;
        }
    }
    const rootCapability = createRootCapability({ controller, invocationTarget: url });
    const wrappedLoader = async (documentUrl) => {
        if (documentUrl === rootCapability.id) {
            return { contextUrl: null, documentUrl, document: rootCapability };
        }
        return documentLoader(documentUrl);
    };
    try {
        const result = await verifyCapabilityInvocation({
            url,
            method,
            headers,
            suite: new Ed25519Signature2020(),
            getVerifier,
            documentLoader: wrappedLoader,
            expectedHost: host,
            expectedAction: method === "GET" ? "read" : "write",
            expectedTarget: url,
            expectedRootCapability: rootCapability.id
        });
        if (!result.verified) {
            console.error("Invocation rejected:", result.error);
            return false;
        }
        return true;
    } catch (error) {
        console.error("Invocation rejected:", error);
        return false;
    }
}
