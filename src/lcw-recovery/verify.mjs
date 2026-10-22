// zCap invocation verification against an account's registered DID: the same
// scheme /login uses. The invoked root capability is controlled by the DID
// registered for the email, so verification itself rejects invocations signed
// by anyone else's key; a registered did:webvh is controlled by the keys its
// log's current document lists (webvh.mjs). Kept in this function's own
// directory because SAM's esbuild build only packages files under the
// function's CodeUri.
import "@interop/http-client";
import { verifyCapabilityInvocation } from "@interop/http-signature-zcap-verify";
import { Ed25519Signature2020 } from "@interop/ed25519-signature";
import { createRootCapability } from "@interop/zcap";
import { documentLoader, getVerifier } from "./webvh.mjs";

// True when `event` carries a zcap invocation of its own URL (the query
// string included, so a signed `email` cannot be swapped) signed by
// `registeredDid`.
export async function verifyAccountInvocation({ event, registeredDid }) {
    const headers = Object.fromEntries(
        Object.entries(event.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value])
    );
    const proto = headers["x-forwarded-proto"] ?? "https";
    const host = headers.host ?? event.requestContext.domainName;
    const query = event.rawQueryString ? `?${event.rawQueryString}` : "";
    const url = `${proto}://${host}${event.rawPath}${query}`;
    const method = event.requestContext.http.method;
    const rootCapability = createRootCapability({ controller: registeredDid, invocationTarget: url });
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
