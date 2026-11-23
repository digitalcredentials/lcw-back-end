import { SFNClient, StartExecutionCommand } from "@aws-sdk/client-sfn";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";

const sfnClient = new SFNClient();
const dynamoClient = new DynamoDBClient();
// The PWS server's coupon table. A registration code is a row there: the
// PWS server spends it when the wallet creates the account Space, and this
// stack mints the rows (src/lcw-registration-codes) and closes a limited
// one when its account is confirmed (src/lcw-create-account).
const COUPONS_TABLE = process.env.COUPONS_TABLE_NAME ?? "pws-coupons";

// Whether the code is one an account may still be registered with: its row
// exists, has not expired (expiresAt, absent = never) and is not closed
// (closedAt, set when an account registered with it is confirmed). The
// row's usesRemaining is not read: the PWS server has already taken this
// registration's use from it by the time the wallet calls here, so it may
// rightly be zero.
async function codeIsOpen(code) {
    if (!code || typeof code !== "string") {
        return false;
    }
    const { Item: row } = await dynamoClient.send(new GetItemCommand({
        TableName: COUPONS_TABLE,
        Key: { coupon: { S: code } },
        ConsistentRead: true
    }));
    if (!row || row.closedAt) {
        return false;
    }
    const expiresAt = row.expiresAt?.S;
    return !(expiresAt && expiresAt <= new Date().toISOString());
}

const json = (statusCode, body) => ({
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
});

export const handler = async (event) => {
    // 1. Extract the registration fields from the JSON POST body
    let email, did, registrationCode, contactOptIn;
    try {
        const rawBody = event.isBase64Encoded
            ? Buffer.from(event.body ?? "", "base64").toString("utf8")
            : event.body;
        ({ email, did, registrationCode, contactOptIn } = JSON.parse(rawBody ?? "{}"));
    } catch {
        return json(400, { error: "Request body must be valid JSON." });
    }

    if (!email || !did) {
        return json(400, { error: "Missing email or did in request body." });
    }

    // 2. Gate registration on the code
    let open;
    try {
        open = await codeIsOpen(registrationCode);
    } catch (error) {
        console.error("Error reading the registration code:", error);
        return json(500, { error: "Registration is not available." });
    }
    if (!open) {
        return json(403, {
            error: "Your registration code isn't valid. Please try again or obtain a new code."
        });
    }

    // 3. Start the registration state machine; it emails the confirmation
    // link and, once confirmed, records the account. The registration code
    // is passed on so that a limited code is closed when the account is
    // recorded; it is not stored with the account. The answer to "Contact
    // me with news and updates" (anything but true is no) is passed on so
    // it is stored with the account.
    try {
        await sfnClient.send(new StartExecutionCommand({
            stateMachineArn: process.env.STATE_MACHINE_ARN,
            input: JSON.stringify({ recipientEmail: email, did, contactOptIn: contactOptIn === true, registrationCode })
        }));
    } catch (error) {
        console.error("Error starting registration execution:", error);
        return json(500, { error: "Registration failed. Please try again later." });
    }

    return json(202, {
        message: "Registration started. Check your email for a confirmation link."
    });
};
