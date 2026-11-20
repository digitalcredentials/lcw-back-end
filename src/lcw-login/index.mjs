// The verifier comes from the webvh-verify layer (layers/webvh-verify),
// shared with lcw-recovery and the batch issuer's notify function.
import { verifyAccountInvocation } from "webvh-verify";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";

const dynamoClient = new DynamoDBClient();
const TABLE_NAME = process.env.TABLE_NAME ?? "lcw-accounts";
const MAX_BADGE_COLLECTIONS = Number(process.env.MAX_BADGE_COLLECTIONS ?? "3");

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
        // A consistent read: the row is written moments before the first
        // login, when the person confirms their email and opens the wallet
        ({ Item: account } = await dynamoClient.send(new GetItemCommand({
            TableName: TABLE_NAME,
            Key: { email: { S: email } },
            ConsistentRead: true
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
    if (!(await verifyAccountInvocation({ event, registeredDid }))) {
        console.error(`Login rejected for ${email}`);
        return json(401, { error: "Login failed." });
    }

    // Identity only: the wallet finds its spaces through the PWS server, and
    // creates further ones under its account Space with a capability on it.
    // Nothing of the registration code is returned (rows written before the
    // code stopped being stored still hold it as `token`; it is not read).
    // `badgeAvailable`: whether the account may still collect the alpha
    // testing badge (src/lcw-badge counts its collections), so the wallet
    // knows whether to offer it without a request of its own.
    return json(200, {
        verified: true,
        email,
        controller: registeredDid,
        badgeAvailable: Number(account.badgeCollections?.N ?? "0") < MAX_BADGE_COLLECTIONS
    });
};
