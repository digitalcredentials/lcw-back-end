import { createHash, randomInt, timingSafeEqual } from "node:crypto";
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";

// POST /registration-codes: mints a registration code for one person and
// answers the code, the link that opens the wallet's registration page with
// the code filled in, and when the code expires. The caller (the alpha
// application app's server) emails the link.
//
// The caller presents the API key held in Parameter Store (a SecureString;
// its name is API_KEY_PARAMETER) in the `x-api-key` header. The key lets
// its holder create wallet accounts, so it belongs on a server, never in a
// page a browser loads.
//
// A code is a row of the PWS server's coupon table. It is for one account:
// it is closed when an account registered with it is confirmed
// (src/lcw-create-account). Until then the PWS server accepts it
// CODE_ATTEMPTS times, so a signup that fails part-way can be tried again
// with the same link.

const dynamoClient = new DynamoDBClient();
const ssmClient = new SSMClient();
const COUPONS_TABLE = process.env.COUPONS_TABLE_NAME ?? "pws-coupons";
const API_KEY_PARAMETER = process.env.API_KEY_PARAMETER ?? "/lcw/registration-codes/api-key";
const WALLET_URL = (process.env.WALLET_URL ?? "https://lcw-sandbox.org").replace(/\/+$/, "");
const CODE_ATTEMPTS = Number(process.env.CODE_ATTEMPTS ?? "5");
const CODE_EXPIRY_DAYS = Number(process.env.CODE_EXPIRY_DAYS ?? "90");
// How long a container keeps the key before it reads the parameter again,
// so a replaced key takes effect without a deploy
const KEY_CACHE_MS = 5 * 60 * 1000;
const ISSUED_TO_MAX = 320;

// 31 characters, with no 0, O, 1, I or L: 16 of them are 79 random bits.
// POST /register tells any caller whether a code is valid, so a code must
// not be guessable.
const CODE_CHARS = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const CODE_LENGTH = 16;

const json = (statusCode, body) => ({
    statusCode,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    body: JSON.stringify(body)
});

export function newCode() {
    let code = "";
    for (let i = 0; i < CODE_LENGTH; i++) {
        code += CODE_CHARS[randomInt(CODE_CHARS.length)];
    }
    return `LCW-${code}`;
}

let cachedKey;
let cachedAt = 0;
async function apiKey() {
    if (!cachedKey || Date.now() - cachedAt > KEY_CACHE_MS) {
        const { Parameter } = await ssmClient.send(new GetParameterCommand({ Name: API_KEY_PARAMETER, WithDecryption: true }));
        cachedKey = Parameter?.Value;
        cachedAt = Date.now();
    }
    return cachedKey;
}

const digest = (value) => createHash("sha256").update(value).digest();

export const handler = async (event) => {
    const headers = Object.fromEntries(Object.entries(event.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value]));
    const presented = headers["x-api-key"];
    let expected;
    try {
        expected = await apiKey();
    } catch (error) {
        console.error("Error reading the API key:", error);
        return json(500, { error: "Registration codes are not available." });
    }
    if (!expected) {
        console.error("The API key parameter is empty");
        return json(500, { error: "Registration codes are not available." });
    }
    if (typeof presented !== "string" || !timingSafeEqual(digest(presented), digest(expected))) {
        return json(401, { error: "Missing or wrong API key." });
    }

    // The body is optional: { issuedTo } is a note of who the code is for
    // (the applicant's email address, say), kept on the row. The code is
    // not tied to it: any email address can register with the code.
    let issuedTo;
    try {
        const rawBody = event.isBase64Encoded ? Buffer.from(event.body ?? "", "base64").toString("utf8") : event.body;
        ({ issuedTo } = rawBody ? JSON.parse(rawBody) ?? {} : {});
    } catch {
        return json(400, { error: "Request body must be valid JSON." });
    }
    if (issuedTo !== undefined && (typeof issuedTo !== "string" || issuedTo.length > ISSUED_TO_MAX)) {
        return json(400, { error: `issuedTo must be a string of at most ${ISSUED_TO_MAX} characters.` });
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + CODE_EXPIRY_DAYS * 24 * 60 * 60 * 1000).toISOString();
    const code = newCode();
    try {
        await dynamoClient.send(new PutItemCommand({
            TableName: COUPONS_TABLE,
            Item: {
                coupon: { S: code },
                usesRemaining: { N: String(CODE_ATTEMPTS) },
                expiresAt: { S: expiresAt },
                issuedAt: { S: now.toISOString() },
                ...(issuedTo && { issuedTo: { S: issuedTo } })
            },
            ConditionExpression: "attribute_not_exists(coupon)"
        }));
    } catch (error) {
        console.error("Error writing the registration code:", error);
        return json(500, { error: "The registration code could not be created. Please try again." });
    }

    return json(201, { code, link: `${WALLET_URL}/#/register?code=${encodeURIComponent(code)}`, expiresAt });
};
