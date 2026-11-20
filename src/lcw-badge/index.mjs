import { randomBytes, timingSafeEqual } from "node:crypto";
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
// From the webvh-verify layer (layers/webvh-verify), shared with lcw-login,
// lcw-recovery and lcw-contact.
import { verifyAccountInvocation } from "webvh-verify";

// The account's grant for the LCW Alpha Testing Badge: what lets the badge's
// issuer tell that a request comes from a wallet account, and issue one
// a limited number of badges per account (MAX_BADGE_COLLECTIONS; more than
// one, so a holder who deletes the badge by accident can collect it again).
// The wallet asks for the grant, signed as the account, and hands it to the
// issuer; the issuer asks here whether it is good, and has a collection
// counted when a badge is issued. The grant's secret, the count and the time
// of the last collection are kept on the account row (`badgeGrant`,
// `badgeCollections`, `badgeCollectedAt`).
//
//   POST /badge-grant         { email }           { grant }   (signed as the account)
//                             409 { collected: true } once the limit is reached
//   POST /badge-grant/redeem  { grant, consume? }  { valid: true }
//                             404 { valid: false }                  no such grant
//                             409 { valid: false, collected: true } limit reached
//
// The redeem route is called by the issuer and is not signed: the grant is
// the secret. Without `consume` it only checks; with it, one collection is
// counted.
//
// A grant is the account's email (base64url) and a random secret, joined by
// a dot, so the row is found by its key.

const dynamo = new DynamoDBClient();
const ACCOUNTS_TABLE = process.env.ACCOUNTS_TABLE_NAME ?? "lcw-accounts";
const MAX_COLLECTIONS = Number(process.env.MAX_BADGE_COLLECTIONS ?? "3");

const collectionsOf = (account) => Number(account?.badgeCollections?.N ?? "0");
const limitReached = (account) => collectionsOf(account) >= MAX_COLLECTIONS;

const json = (statusCode, body) => ({
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
});

const parseBody = (event) => {
    const raw = event.isBase64Encoded ? Buffer.from(event.body ?? "", "base64").toString("utf8") : event.body;
    return JSON.parse(raw ?? "{}");
};

async function getAccount(email) {
    const { Item } = await dynamo.send(new GetItemCommand({ TableName: ACCOUNTS_TABLE, Key: { email: { S: email } } }));
    return Item;
}

// The registered DID may carry a key fragment.
const registeredDidOf = (account) => account?.did?.S?.split("#")[0];

async function authenticate(event, email) {
    const account = await getAccount(email);
    const registeredDid = registeredDidOf(account);
    if (!registeredDid || !(await verifyAccountInvocation({ event, registeredDid }))) {
        return null;
    }
    return account;
}

const grantOf = (email, secret) => `${Buffer.from(email, "utf8").toString("base64url")}.${secret}`;

function partsOf(grant) {
    if (typeof grant !== "string" || grant.length > 1024) {
        return null;
    }
    const [encoded, secret, ...rest] = grant.split(".");
    if (!encoded || !secret || rest.length) {
        return null;
    }
    return { email: Buffer.from(encoded, "base64url").toString("utf8"), secret };
}

const same = (a, b) => {
    const left = Buffer.from(a, "utf8");
    const right = Buffer.from(b, "utf8");
    return left.length === right.length && timingSafeEqual(left, right);
};

// The account's grant, made on the first request and the same on every
// later one, until the account has collected as many badges as it may.
async function grant(event) {
    let email;
    try {
        ({ email } = parseBody(event));
    } catch {
        return json(400, { error: "Request body must be valid JSON." });
    }
    if (!email || typeof email !== "string") {
        return json(400, { error: "An email is required." });
    }
    let account = await authenticate(event, email);
    if (!account) {
        return json(401, { error: "Unauthorized." });
    }
    if (limitReached(account)) {
        return json(409, { error: "This account has already collected its badge.", collected: true });
    }
    if (!account.badgeGrant?.S) {
        await dynamo.send(
            new UpdateItemCommand({
                TableName: ACCOUNTS_TABLE,
                Key: { email: { S: email } },
                UpdateExpression: "SET badgeGrant = if_not_exists(badgeGrant, :secret)",
                ConditionExpression: "attribute_exists(email)",
                ExpressionAttributeValues: { ":secret": { S: randomBytes(32).toString("base64url") } },
                ReturnValues: "NONE"
            })
        );
        // Read back: two requests at once agree on the one that was stored
        account = await getAccount(email);
    }
    return json(200, { grant: grantOf(email, account.badgeGrant.S) });
}

async function redeem(event) {
    let body;
    try {
        body = parseBody(event);
    } catch {
        return json(400, { error: "Request body must be valid JSON." });
    }
    const parts = partsOf(body.grant);
    const account = parts && (await getAccount(parts.email));
    if (!account?.badgeGrant?.S || !same(account.badgeGrant.S, parts.secret)) {
        return json(404, { valid: false });
    }
    if (limitReached(account)) {
        return json(409, { valid: false, collected: true });
    }
    if (body.consume === true) {
        try {
            await dynamo.send(
                new UpdateItemCommand({
                    TableName: ACCOUNTS_TABLE,
                    Key: { email: { S: parts.email } },
                    UpdateExpression: "SET badgeCollectedAt = :at ADD badgeCollections :one",
                    ConditionExpression: "badgeGrant = :secret AND (attribute_not_exists(badgeCollections) OR badgeCollections < :max)",
                    ExpressionAttributeValues: {
                        ":at": { S: new Date().toISOString() },
                        ":secret": { S: parts.secret },
                        ":one": { N: "1" },
                        ":max": { N: String(MAX_COLLECTIONS) }
                    },
                    ReturnValues: "NONE"
                })
            );
        } catch (error) {
            if (error.name === "ConditionalCheckFailedException") {
                // Other requests reached the limit between the read and the write
                return json(409, { valid: false, collected: true });
            }
            throw error;
        }
        console.log(`Badge collected by ${parts.email}`);
    }
    return json(200, { valid: true });
}

export const handler = async (event) => {
    const method = event.requestContext?.http?.method;
    try {
        if (event.rawPath === "/badge-grant" && method === "POST") {
            return await grant(event);
        }
        if (event.rawPath === "/badge-grant/redeem" && method === "POST") {
            return await redeem(event);
        }
        return json(404, { error: "Not found." });
    } catch (error) {
        console.error("Badge grant request failed:", error);
        return json(500, { error: "The badge grant could not be read or used." });
    }
};
