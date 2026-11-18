import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
// From the webvh-verify layer (layers/webvh-verify), shared with lcw-login
// and lcw-recovery.
import { verifyAccountInvocation } from "webvh-verify";

// The tester's answer to "Contact me with news and updates", kept on the
// account row (`contactOptIn`, `contactOptInUpdatedAt`). The registration
// state machine writes it with the row; the wallet's Settings read and
// change it here:
//
//   GET /contact?email=...                { contactOptIn, updatedAt? }  (signed as the account)
//   PUT /contact  { email, contactOptIn }  { contactOptIn, updatedAt }   (signed as the account)
//
// A row without the attribute (an account registered before the question
// was asked) reads as no.

const dynamo = new DynamoDBClient();
const ACCOUNTS_TABLE = process.env.ACCOUNTS_TABLE_NAME ?? "lcw-accounts";

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

const choiceOf = (account) => ({
    contactOptIn: account.contactOptIn?.BOOL === true,
    ...(account.contactOptInUpdatedAt?.S && { updatedAt: account.contactOptInUpdatedAt.S })
});

async function status(event) {
    const email = event.queryStringParameters?.email;
    if (!email) {
        return json(400, { error: "Missing email." });
    }
    const account = await authenticate(event, email);
    if (!account) {
        return json(401, { error: "Unauthorized." });
    }
    return json(200, choiceOf(account));
}

async function change(event) {
    let email, contactOptIn;
    try {
        ({ email, contactOptIn } = parseBody(event));
    } catch {
        return json(400, { error: "Request body must be valid JSON." });
    }
    if (!email || typeof contactOptIn !== "boolean") {
        return json(400, { error: "An email and a true or false contactOptIn are required." });
    }
    if (!(await authenticate(event, email))) {
        return json(401, { error: "Unauthorized." });
    }
    const updatedAt = new Date().toISOString();
    await dynamo.send(
        new UpdateItemCommand({
            TableName: ACCOUNTS_TABLE,
            Key: { email: { S: email } },
            UpdateExpression: "SET contactOptIn = :choice, contactOptInUpdatedAt = :at",
            ConditionExpression: "attribute_exists(email)",
            ExpressionAttributeValues: { ":choice": { BOOL: contactOptIn }, ":at": { S: updatedAt } },
            ReturnValues: "NONE"
        })
    );
    console.log(`Contact choice for ${email}: ${contactOptIn ? "agreed" : "declined"}`);
    return json(200, { contactOptIn, updatedAt });
}

export const handler = async (event) => {
    const method = event.requestContext?.http?.method;
    try {
        if (event.rawPath === "/contact" && method === "GET") {
            return await status(event);
        }
        if (event.rawPath === "/contact" && method === "PUT") {
            return await change(event);
        }
        return json(404, { error: "Not found." });
    } catch (error) {
        console.error("Contact choice request failed:", error);
        return json(500, { error: "The contact choice could not be read or changed." });
    }
};
