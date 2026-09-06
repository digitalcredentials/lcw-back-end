// Must be evaluated before @interop/jsonld (CJS) is pulled in below, which
// require()s this ESM package mid-graph and hits a TDZ error otherwise.
import "@interop/http-client";
import { verifyCapabilityInvocation } from "@interop/http-signature-zcap-verify";
import { Ed25519Signature2020 } from "@interop/ed25519-signature";
import { securityLoader } from "@interop/security-document-loader";
import { Ed25519VerificationKey } from "@interop/ed25519-verification-key";

const documentLoader = securityLoader().build();

async function getVerifier({ keyId, documentLoader }) {
    const { document } = await documentLoader(keyId);
    const key = await Ed25519VerificationKey.fromKeyDocument({ document });
    return { verifier: key.verifier(), verificationMethod: document };
}

const json = (statusCode, body) => ({
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
});

export const handler = async (event) => {
    // 1. Extract the email from the JSON POST body
    let email;
    try {
        const rawBody = event.isBase64Encoded
            ? Buffer.from(event.body ?? "", "base64").toString("utf8")
            : event.body;
        email = JSON.parse(rawBody ?? "{}").email;
    } catch {
        return json(400, { error: "Request body must be valid JSON." });
    }

    if (!email) {
        return json(400, { error: "Missing email in request body." });
    }

    // 2. Verify the zCap HTTP-signature invocation headers
    const host = event.requestContext.domainName;
    const url = `https://${host}${event.rawPath}`;

    try {
        const result = await verifyCapabilityInvocation({
            url,
            method: event.requestContext.http.method,
            headers: event.headers,
            suite: new Ed25519Signature2020(),
            getVerifier,
            documentLoader,
            expectedHost: host,
            expectedAction: "write",
            expectedTarget: url,
            expectedRootCapability: `urn:zcap:root:${encodeURIComponent(url)}`
        });

        if (!result.verified) {
            console.error("zCap verification failed:", result.error);
            return json(401, { error: "Invalid capability invocation signature." });
        }

        // 3. Signature checks out — the caller controls the invoking key
        return json(200, {
            verified: true,
            email,
            controller: result.controller
        });
    } catch (error) {
        console.error("Error verifying capability invocation:", error);
        return json(401, { error: "Invalid capability invocation signature." });
    }
};
