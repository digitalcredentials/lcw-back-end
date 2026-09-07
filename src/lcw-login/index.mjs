// Must be evaluated before @interop/jsonld (CJS) is pulled in below, which
// require()s this ESM package mid-graph and hits a TDZ error otherwise.
import "@interop/http-client";
import { verifyCapabilityInvocation } from "@interop/http-signature-zcap-verify";
import { Ed25519Signature2020 } from "@interop/ed25519-signature";
import { securityLoader } from "@interop/security-document-loader";
import { Ed25519VerificationKey } from "@interop/ed25519-verification-key";
import { createRootCapability } from "@interop/zcap";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";

const documentLoader = securityLoader().build();
const dynamoClient = new DynamoDBClient();
const TABLE_NAME = process.env.TABLE_NAME ?? "wallet-test";

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

    // 2. Look up the account so the registered DID can control the root zcap
    let account;
    try {
        ({ Item: account } = await dynamoClient.send(new GetItemCommand({
            TableName: TABLE_NAME,
            Key: { email: { S: email } }
        })));
    } catch (error) {
        console.error("Error looking up account:", error);
        return json(500, { error: "Failed to look up account." });
    }

    // Stored DIDs may carry a key fragment (did:key:z6Mk...#z6Mk...)
    const registeredDid = account?.did?.S?.split("#")[0];
    if (!registeredDid) {
        console.error(`Login rejected for ${email}: no registered account`);
        return json(401, { error: "Login failed." });
    }

    // 3. Verify the zCap HTTP-signature invocation headers. The root
    // capability for /login is controlled by the account's registered DID, so
    // verification itself rejects invocations signed by anyone else's key.
    const host = event.requestContext.domainName;
    const url = `https://${host}${event.rawPath}`;
    const rootCapability = createRootCapability({
        controller: registeredDid,
        invocationTarget: url
    });
    const loginDocumentLoader = async (documentUrl) => {
        if (documentUrl === rootCapability.id) {
            return { contextUrl: null, documentUrl, document: rootCapability };
        }
        return documentLoader(documentUrl);
    };

    try {
        const result = await verifyCapabilityInvocation({
            url,
            method: event.requestContext.http.method,
            headers: event.headers,
            suite: new Ed25519Signature2020(),
            getVerifier,
            documentLoader: loginDocumentLoader,
            expectedHost: host,
            expectedAction: "write",
            expectedTarget: url,
            expectedRootCapability: rootCapability.id
        });

        if (!result.verified) {
            console.error(`Login rejected for ${email}:`, result.error);
            return json(401, { error: "Login failed." });
        }
    } catch (error) {
        console.error(`Login rejected for ${email}:`, error);
        return json(401, { error: "Login failed." });
    }

    return json(200, {
        verified: true,
        email,
        controller: registeredDid,
        bucket: account.bucket?.S
    });
};
