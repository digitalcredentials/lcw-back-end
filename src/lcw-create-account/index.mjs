import { DynamoDBClient, GetItemCommand, PutItemCommand, TransactWriteItemsCommand } from "@aws-sdk/client-dynamodb";

// The registration state machine's account step, run once the person has
// confirmed their email address: it writes the account row and, when the
// registration code is a limited one, closes the code in the same
// transaction.
//
// A limited code (a row of the PWS server's coupon table with
// usesRemaining) is for one account. The PWS server takes one use from it
// each time a wallet starts creating an account Space, and a signup that
// fails part-way leaves that use spent, so a code is minted with several
// uses (src/lcw-registration-codes) and is closed only here, when an
// account made with it is complete: closedAt is set and usesRemaining
// becomes zero, after which neither the PWS server nor POST /register
// accepts it. Two accounts confirmed with one code cannot both be
// recorded: the second transaction fails its condition and this function
// throws CodeAlreadyUsed, which the state machine catches. The closed row
// records the confirmation key it was closed for (closedFor, the hash of
// the confirmation link's token, no personal data), so a retry of the step
// that closed it succeeds.
//
// A code with no usesRemaining (the deployment's shared code) is never
// closed.

const dynamoClient = new DynamoDBClient();
const ACCOUNTS_TABLE = process.env.ACCOUNTS_TABLE_NAME ?? "lcw-accounts";
const COUPONS_TABLE = process.env.COUPONS_TABLE_NAME ?? "pws-coupons";

export class CodeAlreadyUsed extends Error {
    constructor() {
        super("The registration code was used for another account, or no longer exists.");
        this.name = "CodeAlreadyUsed";
    }
}

export const handler = async ({ email, did, contactOptIn, confirmationKey, registrationCode }) => {
    if (!email || !did) {
        throw new Error("Missing email or did.");
    }
    const now = new Date().toISOString();
    // The account row is identity (email -> did) and the tester's contact
    // choice; the account's Spaces live in the PWS server. confirmationKey
    // is the hash of the confirmation link's task token, which the
    // confirmation page polls the row by (GET /confirm/status).
    const account = {
        email: { S: email },
        did: { S: did },
        confirmationKey: { S: confirmationKey || "none" },
        CreatedAt: { S: now },
        contactOptIn: { BOOL: contactOptIn === true },
        contactOptInUpdatedAt: { S: now }
    };

    const { Item: code } = registrationCode
        ? await dynamoClient.send(new GetItemCommand({
            TableName: COUPONS_TABLE,
            Key: { coupon: { S: registrationCode } },
            ConsistentRead: true
        }))
        : {};
    if (!code) {
        // POST /register found the row; it has been removed since
        throw new CodeAlreadyUsed();
    }
    if (code.closedAt && confirmationKey && code.closedFor?.S === confirmationKey) {
        // A retry: this confirmation already closed the code and wrote the row
        return { email, codeClosed: true };
    }
    if (code.usesRemaining === undefined) {
        await dynamoClient.send(new PutItemCommand({ TableName: ACCOUNTS_TABLE, Item: account }));
        return { email, codeClosed: false };
    }

    try {
        await dynamoClient.send(new TransactWriteItemsCommand({
            TransactItems: [
                { Put: { TableName: ACCOUNTS_TABLE, Item: account } },
                {
                    Update: {
                        TableName: COUPONS_TABLE,
                        Key: { coupon: { S: registrationCode } },
                        UpdateExpression: "SET closedAt = :now, closedFor = :key, usesRemaining = :zero",
                        ConditionExpression: "attribute_exists(coupon) AND attribute_not_exists(closedAt)",
                        ExpressionAttributeValues: { ":now": { S: now }, ":key": { S: confirmationKey || "none" }, ":zero": { N: "0" } }
                    }
                }
            ]
        }));
    } catch (error) {
        const reasons = error.CancellationReasons ?? [];
        if (error.name === "TransactionCanceledException" && reasons[1]?.Code === "ConditionalCheckFailed") {
            throw new CodeAlreadyUsed();
        }
        throw error;
    }
    return { email, codeClosed: true };
};
