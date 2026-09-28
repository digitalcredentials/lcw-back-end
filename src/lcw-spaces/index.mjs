// Manages the account's Wallet Attached Storage spaces:
//
//   POST   /spaces                          create a space  {email, type, name?}
//   GET    /spaces?email=...                list the account's spaces
//   DELETE /spaces?email=...&space=<url>    delete a batch space
//
// Every request must be a zcap invocation of its own URL signed by the DID
// registered for the email (see verify.mjs) — the same auth scheme as /login.
//
// Must be evaluated before @interop/jsonld (CJS) is pulled in below, which
// require()s this ESM package mid-graph and hits a TDZ error otherwise.
import "@interop/http-client";
import { randomUUID } from "node:crypto";
import {
    DynamoDBClient,
    GetItemCommand,
    PutItemCommand,
    QueryCommand,
    DeleteItemCommand
} from "@aws-sdk/client-dynamodb";
import {
    S3Client,
    CreateBucketCommand,
    PutObjectCommand,
    ListObjectsV2Command,
    DeleteObjectsCommand,
    DeleteBucketCommand
} from "@aws-sdk/client-s3";
import { verifyAccountInvocation } from "./verify.mjs";

const dynamoClient = new DynamoDBClient();
const s3 = new S3Client();

const ACCOUNTS_TABLE = process.env.TABLE_NAME ?? "wallet-test";
const SPACES_TABLE = process.env.SPACES_TABLE_NAME ?? "wallet-spaces";
const SPACE_URL_BASE = (process.env.SPACE_URL_BASE ?? "https://was.example.org/space").replace(/\/+$/, "");

const SPACE_TYPES = new Set(["credential", "batch"]);

const json = (statusCode, body) => ({
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
});

function spaceFromItem(item) {
    return {
        url: item.spaceURL?.S,
        type: item.type?.S,
        name: item.name?.S,
        createdAt: item.CreatedAt?.S
    };
}

async function createSpace({ email, did, type, name }) {
    const bucketName = `dcc-was-${randomUUID()}`;
    const spaceURL = `${SPACE_URL_BASE}/${bucketName}`;
    const spaceName = name || `${email}'s ${type} space`;

    await s3.send(new CreateBucketCommand({ Bucket: bucketName }));
    // The WAS server reads the space description from metadata/description.json
    // (same seed shape as the wallet-account-creator state machine writes).
    await s3.send(new PutObjectCommand({
        Bucket: bucketName,
        Key: "metadata/description.json",
        ContentType: "application/json",
        Body: JSON.stringify({
            name: spaceName,
            type: ["Space"],
            controller: did,
            createdBy: did
        })
    }));
    await dynamoClient.send(new PutItemCommand({
        TableName: SPACES_TABLE,
        Item: {
            spaceURL: { S: spaceURL },
            email: { S: email },
            did: { S: did },
            type: { S: type },
            name: { S: spaceName },
            CreatedAt: { S: new Date().toISOString() }
        }
    }));
    return { space: spaceURL, type, name: spaceName };
}

async function listSpaces({ email }) {
    const { Items: items = [] } = await dynamoClient.send(new QueryCommand({
        TableName: SPACES_TABLE,
        IndexName: "by-email",
        KeyConditionExpression: "email = :email",
        ExpressionAttributeValues: { ":email": { S: email } }
    }));
    return { spaces: items.map(spaceFromItem) };
}

async function deleteSpace({ email, spaceURL }) {
    const { Item: item } = await dynamoClient.send(new GetItemCommand({
        TableName: SPACES_TABLE,
        Key: { spaceURL: { S: spaceURL } }
    }));
    // 404 for a space that doesn't exist OR belongs to another account, so
    // nothing is revealed about other accounts' spaces.
    if (!item || item.email?.S !== email) {
        return json(404, { error: "No such space." });
    }
    if (item.type?.S !== "batch") {
        return json(403, { error: "Only batch spaces can be deleted." });
    }

    const bucketName = spaceURL.split("/").pop();
    // Empty the bucket, then delete it. NoSuchBucket is tolerated so a
    // half-deleted space can be cleaned up by retrying.
    try {
        let ContinuationToken;
        do {
            const page = await s3.send(new ListObjectsV2Command({
                Bucket: bucketName,
                ContinuationToken
            }));
            const objects = (page.Contents ?? []).map(({ Key }) => ({ Key }));
            if (objects.length) {
                await s3.send(new DeleteObjectsCommand({
                    Bucket: bucketName,
                    Delete: { Objects: objects }
                }));
            }
            ContinuationToken = page.IsTruncated ? page.NextContinuationToken : undefined;
        } while (ContinuationToken);
        await s3.send(new DeleteBucketCommand({ Bucket: bucketName }));
    } catch (error) {
        if (error.name !== "NoSuchBucket") {
            throw error;
        }
    }

    await dynamoClient.send(new DeleteItemCommand({
        TableName: SPACES_TABLE,
        Key: { spaceURL: { S: spaceURL } }
    }));
    return { statusCode: 204, body: "" };
}

export const handler = async (event) => {
    const method = event.requestContext?.http?.method;
    const query = event.queryStringParameters ?? {};

    // The email identifying the account: in the body for POST, in the query
    // string (covered by the signed URL) for GET and DELETE.
    let body = {};
    if (method === "POST") {
        try {
            const rawBody = event.isBase64Encoded
                ? Buffer.from(event.body ?? "", "base64").toString("utf8")
                : event.body;
            body = JSON.parse(rawBody ?? "{}");
        } catch {
            return json(400, { error: "Request body must be valid JSON." });
        }
    }
    const email = method === "POST" ? body.email : query.email;
    if (!email) {
        return json(400, { error: "Missing email." });
    }

    // Look up the account so the registered DID can control the root zcap.
    let account;
    try {
        ({ Item: account } = await dynamoClient.send(new GetItemCommand({
            TableName: ACCOUNTS_TABLE,
            Key: { email: { S: email } }
        })));
    } catch (error) {
        console.error("Error looking up account:", error);
        return json(500, { error: "Failed to look up account." });
    }
    // Stored DIDs may carry a key fragment (did:key:z6Mk...#z6Mk...)
    const registeredDid = account?.did?.S?.split("#")[0];
    if (!registeredDid || !(await verifyAccountInvocation({ event, registeredDid }))) {
        return json(401, { error: "Unauthorized." });
    }

    try {
        if (method === "POST") {
            const { type, name } = body;
            if (!SPACE_TYPES.has(type)) {
                return json(400, { error: `type must be one of: ${[...SPACE_TYPES].join(", ")}` });
            }
            return json(201, await createSpace({ email, did: registeredDid, type, name }));
        }
        if (method === "GET") {
            return json(200, await listSpaces({ email }));
        }
        if (method === "DELETE") {
            const spaceURL = query.space;
            if (!spaceURL) {
                return json(400, { error: "Missing space query parameter." });
            }
            return await deleteSpace({ email, spaceURL });
        }
        return json(405, { error: "Method not allowed." });
    } catch (error) {
        console.error(`Spaces ${method} failed for ${email}:`, error);
        return json(500, { error: "Server error." });
    }
};
