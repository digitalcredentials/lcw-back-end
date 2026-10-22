import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { KMSClient, EncryptCommand, DecryptCommand } from "@aws-sdk/client-kms";
import { SESv2Client, SendEmailCommand } from "@aws-sdk/client-sesv2";
import { verifyAccountInvocation } from "./verify.mjs";

// The account's recovery code. The wallet mints a code, binds it as a
// credential of the account, and stores it here, encrypted under a KMS key,
// so that "Forgot your password?" can email it to the address the account
// registered. Whoever can read this table AND decrypt with the key AND
// receive that mail can open the account's data: the server holds a secret
// that unlocks the account, the one place this design does not keep the
// server unable to read user data. It is encrypted at rest, sent only to the
// registered address, rate limited, logged, and replaced by the wallet after
// every use.
//
//   PUT  /recovery    { email, code }   store or replace the code (signed as the account)
//   GET  /recovery?email=...            { stored: boolean }       (signed as the account)
//   POST /forgot      { email }         email the code to the registered address; the
//                                       answer is the same whether or not the account
//                                       or a code exists

const dynamo = new DynamoDBClient();
const kms = new KMSClient();
const ses = new SESv2Client();

const ACCOUNTS_TABLE = process.env.ACCOUNTS_TABLE_NAME ?? "wallet-test";
const RECOVERY_TABLE = process.env.RECOVERY_TABLE_NAME ?? "lcw-recovery";
const KEY_ID = process.env.RECOVERY_KEY_ID;
const FROM_EMAIL = process.env.FROM_EMAIL;
const ORG_NAME = process.env.ORG_NAME ?? "";
const LOGO_URL = process.env.LOGO_URL ?? "";
const WALLET_URL = (process.env.WALLET_URL ?? "").replace(/\/+$/, "");
// At most this many recovery emails per address per window
const MAX_SENDS = Number(process.env.MAX_SENDS ?? "3");
const WINDOW_SECONDS = Number(process.env.WINDOW_SECONDS ?? "3600");
const MAX_CODE_LENGTH = 256;

const json = (statusCode, body) => ({
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? "" : JSON.stringify(body)
});

const parseBody = (event) => {
    const raw = event.isBase64Encoded ? Buffer.from(event.body ?? "", "base64").toString("utf8") : event.body;
    return JSON.parse(raw ?? "{}");
};

const escapeHtml = (text) =>
    String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

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

async function storeCode(event) {
    let email, code;
    try {
        ({ email, code } = parseBody(event));
    } catch {
        return json(400, { error: "Request body must be valid JSON." });
    }
    if (!email || typeof code !== "string" || !code || code.length > MAX_CODE_LENGTH) {
        return json(400, { error: "An email and a recovery code are required." });
    }
    if (!(await authenticate(event, email))) {
        return json(401, { error: "Unauthorized." });
    }
    const { CiphertextBlob } = await kms.send(
        new EncryptCommand({
            KeyId: KEY_ID,
            Plaintext: Buffer.from(code, "utf8"),
            EncryptionContext: { email }
        })
    );
    await dynamo.send(
        new PutItemCommand({
            TableName: RECOVERY_TABLE,
            Item: {
                email: { S: email },
                code: { B: CiphertextBlob },
                updatedAt: { S: new Date().toISOString() },
                windowStart: { N: "0" },
                sends: { N: "0" }
            }
        })
    );
    console.log(`Recovery code stored for ${email}`);
    // A body, not a 204: the zcap HTTP client parses every response as JSON
    return json(200, { stored: true });
}

async function status(event) {
    const email = event.queryStringParameters?.email;
    if (!email) {
        return json(400, { error: "Missing email." });
    }
    if (!(await authenticate(event, email))) {
        return json(401, { error: "Unauthorized." });
    }
    const { Item } = await dynamo.send(new GetItemCommand({ TableName: RECOVERY_TABLE, Key: { email: { S: email } } }));
    return json(200, { stored: Boolean(Item?.code?.B) });
}

function emailBody({ code }) {
    const link = WALLET_URL ? `${WALLET_URL}/forgot` : "";
    const text =
        "You asked to recover your Learner Credential Wallet account.\n\n" +
        `Your recovery code is:\n\n${code}\n\n` +
        (link ? `Enter it at ${link}, then choose a new password.\n\n` : "Enter it on the wallet's recovery page, then choose a new password.\n\n") +
        "If you did not ask for this, you can ignore this email; your account has not changed.";
    const html =
        "<!doctype html><html><body style='margin:0;padding:0;background:#f3f4f6;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1f2937;'>" +
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' style='background:#f3f4f6;padding:24px 0;'><tr><td align='center'>" +
        "<table role='presentation' width='560' cellpadding='0' cellspacing='0' style='max-width:560px;width:100%;background:#ffffff;border-radius:12px;border:1px solid #e5e7eb;'>" +
        `<tr><td style='padding:24px 32px 8px 32px;'>${LOGO_URL ? `<img src='${escapeHtml(LOGO_URL)}' alt='' width='44' height='44' style='vertical-align:middle;border:0;'>` : ""}` +
        `<span style='font-size:16px;font-weight:600;vertical-align:middle;margin-left:10px;'>${escapeHtml(ORG_NAME)}</span></td></tr>` +
        "<tr><td style='padding:8px 32px 32px 32px;font-size:16px;line-height:1.5;'>" +
        "<h1 style='font-size:22px;margin:16px 0;'>Recover your account</h1>" +
        "<p>You asked to recover your Learner Credential Wallet account. Your recovery code is:</p>" +
        `<p style='margin:20px 0;padding:14px 16px;background:#f3f4f6;border-radius:8px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:15px;word-break:break-all;'>${escapeHtml(code)}</p>` +
        (link ? `<p>Enter it on the <a href='${escapeHtml(link)}'>recovery page</a>, then choose a new password.</p>` : "<p>Enter it on the wallet's recovery page, then choose a new password.</p>") +
        "<p style='font-size:14px;color:#6b7280;'>If you did not ask for this, you can ignore this email; your account has not changed.</p>" +
        "</td></tr>" +
        `<tr><td style='padding:16px 32px;border-top:1px solid #e5e7eb;font-size:13px;color:#6b7280;'>${escapeHtml(ORG_NAME)} &middot; Learner Credential Wallet</td></tr>` +
        "</table></td></tr></table></body></html>";
    return { text, html };
}

// Takes one send from the address's window, or reports that the window is
// spent. The window restarts once it has passed.
async function takeSend(email, now) {
    const { Item } = await dynamo.send(new GetItemCommand({ TableName: RECOVERY_TABLE, Key: { email: { S: email } } }));
    if (!Item?.code?.B) {
        return null;
    }
    const start = Number(Item.windowStart?.N ?? "0");
    const sends = Number(Item.sends?.N ?? "0");
    const fresh = now - start >= WINDOW_SECONDS;
    if (!fresh && sends >= MAX_SENDS) {
        return { limited: true };
    }
    await dynamo.send(
        new UpdateItemCommand({
            TableName: RECOVERY_TABLE,
            Key: { email: { S: email } },
            UpdateExpression: "SET windowStart = :start, sends = :sends",
            ExpressionAttributeValues: {
                ":start": { N: String(fresh ? now : start) },
                ":sends": { N: String(fresh ? 1 : sends + 1) }
            }
        })
    );
    return { code: Item.code.B };
}

async function forgot(event) {
    let email;
    try {
        ({ email } = parseBody(event));
    } catch {
        return json(400, { error: "Request body must be valid JSON." });
    }
    if (typeof email !== "string" || !email.includes("@")) {
        return json(400, { error: "A valid email is required." });
    }
    // The same answer whatever happens below, so the address of a registered
    // account cannot be learned from this route.
    const answer = json(202, { message: "If that address has an account, a recovery code has been emailed to it." });
    try {
        const account = await getAccount(email);
        if (!account) {
            return answer;
        }
        const taken = await takeSend(email, Math.floor(Date.now() / 1000));
        if (!taken) {
            return answer;
        }
        if (taken.limited) {
            console.warn(`Recovery email rate limit reached for ${email}`);
            return answer;
        }
        const { Plaintext } = await kms.send(
            new DecryptCommand({ KeyId: KEY_ID, CiphertextBlob: taken.code, EncryptionContext: { email } })
        );
        const code = Buffer.from(Plaintext).toString("utf8");
        const { text, html } = emailBody({ code });
        await ses.send(
            new SendEmailCommand({
                FromEmailAddress: FROM_EMAIL,
                Destination: { ToAddresses: [email] },
                Content: {
                    Simple: {
                        Subject: { Data: "Your Learner Credential Wallet recovery code" },
                        Body: { Text: { Data: text }, Html: { Data: html } }
                    }
                }
            })
        );
        console.log(`Recovery code emailed to ${email}`);
    } catch (error) {
        console.error("Recovery email failed:", error);
    }
    return answer;
}

export const handler = async (event) => {
    const method = event.requestContext?.http?.method;
    const path = event.rawPath;
    try {
        if (path === "/forgot" && method === "POST") {
            return await forgot(event);
        }
        if (path === "/recovery" && method === "PUT") {
            return await storeCode(event);
        }
        if (path === "/recovery" && method === "GET") {
            return await status(event);
        }
        return json(404, { error: "Not found." });
    } catch (error) {
        console.error("Recovery request failed:", error);
        return json(500, { error: "Server error." });
    }
};
