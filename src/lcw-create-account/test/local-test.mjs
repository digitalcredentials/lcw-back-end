// Local test for the lcw-create-account handler: runs it in-process with
// an in-memory stand-in for the two tables.
//
//   cd src/lcw-create-account && npm install && npm test
import { DynamoDBClient, GetItemCommand, PutItemCommand, TransactWriteItemsCommand } from "@aws-sdk/client-dynamodb";
import { mockClient } from "aws-sdk-client-mock";

const { handler } = await import("../index.mjs");
const ddb = mockClient(DynamoDBClient);

let accounts;
let coupons;
function reset(rows) {
    accounts = new Map();
    coupons = new Map(Object.entries(rows));
    ddb.reset();
    ddb.on(GetItemCommand).callsFake(({ Key }) => ({ Item: coupons.get(Key.coupon.S) }));
    ddb.on(PutItemCommand).callsFake(({ Item }) => { accounts.set(Item.email.S, Item); return {}; });
    ddb.on(TransactWriteItemsCommand).callsFake(({ TransactItems: [put, update] }) => {
        const row = coupons.get(update.Update.Key.coupon.S);
        if (!row || row.closedAt) {
            throw Object.assign(new Error("cancelled"), { name: "TransactionCanceledException", CancellationReasons: [{ Code: "None" }, { Code: "ConditionalCheckFailed" }] });
        }
        row.closedAt = update.Update.ExpressionAttributeValues[":now"];
        row.usesRemaining = update.Update.ExpressionAttributeValues[":zero"];
        row.closedFor = update.Update.ExpressionAttributeValues[":key"];
        accounts.set(put.Put.Item.email.S, put.Put.Item);
        return {};
    });
}

let failures = 0;
const check = (label, ok, detail) => {
    console.log(`${ok ? "ok  " : "FAIL"} ${label}${detail !== undefined ? ` (${JSON.stringify(detail)})` : ""}`);
    if (!ok) failures++;
};
const input = (extra) => ({ email: "a@b.com", did: "did:webvh:abc:example.org", contactOptIn: true, confirmationKey: "k".repeat(64), ...extra });
const thrown = async (work) => { try { await work(); return null; } catch (error) { return error; } };

// A limited code
reset({ "LCW-ONE": { coupon: { S: "LCW-ONE" }, usesRemaining: { N: "4" } } });
const first = await handler(input({ registrationCode: "LCW-ONE" }));
const row = accounts.get("a@b.com");
check("a limited code: the account is recorded", first.codeClosed === true && row?.did.S === "did:webvh:abc:example.org" && row.contactOptIn.BOOL === true && row.confirmationKey.S === "k".repeat(64) && Boolean(row.CreatedAt.S));
check("the code is not stored with the account", !JSON.stringify(row).includes("LCW-ONE"));
check("and the code is closed with no uses left", Boolean(coupons.get("LCW-ONE").closedAt?.S) && coupons.get("LCW-ONE").usesRemaining.N === "0");
const update = ddb.commandCalls(TransactWriteItemsCommand)[0].args[0].input.TransactItems[1].Update;
check("the close is conditional on the code not being closed", update.ConditionExpression === "attribute_exists(coupon) AND attribute_not_exists(closedAt)");

const again = await handler(input({ registrationCode: "LCW-ONE" }));
check("the same confirmation run again succeeds without a second write", again.codeClosed === true && ddb.commandCalls(TransactWriteItemsCommand).length === 1);
const second = await thrown(() => handler(input({ email: "c@d.com", confirmationKey: "m".repeat(64), registrationCode: "LCW-ONE" })));
check("a second account with the same code is refused by name", second?.name === "CodeAlreadyUsed");
check("and is not recorded", !accounts.has("c@d.com"));

// A limited code with no uses left that was never closed: every attempt
// was spent at the PWS server, the last of them by this registration
reset({ "LCW-LAST": { coupon: { S: "LCW-LAST" }, usesRemaining: { N: "0" } } });
const last = await handler(input({ registrationCode: "LCW-LAST" }));
check("a code whose last use this registration took: recorded and closed", last.codeClosed === true && accounts.has("a@b.com"));

// The deployment's shared code
reset({ SHARED: { coupon: { S: "SHARED" } } });
const shared = await handler(input({ registrationCode: "SHARED", contactOptIn: "yes" }));
check("an unlimited code: the account is recorded", shared.codeClosed === false && accounts.get("a@b.com")?.contactOptIn.BOOL === false);
check("and the code is left as it was", JSON.stringify(coupons.get("SHARED")) === JSON.stringify({ coupon: { S: "SHARED" } }) && ddb.commandCalls(TransactWriteItemsCommand).length === 0);
await handler(input({ email: "c@d.com", registrationCode: "SHARED" }));
check("a second account with it is recorded too", accounts.has("c@d.com"));

// A code whose row is gone, and no code
reset({});
check("a code removed since registration started is refused by name", (await thrown(() => handler(input({ registrationCode: "GONE" }))))?.name === "CodeAlreadyUsed" && accounts.size === 0);
check("no code is refused by name", (await thrown(() => handler(input({}))))?.name === "CodeAlreadyUsed" && accounts.size === 0);
check("no email is an error", (await thrown(() => handler({ did: "did:key:z6Mk" })))?.message === "Missing email or did.");

// Any other failure of the transaction is passed on, not read as a used code
reset({ "LCW-ONE": { coupon: { S: "LCW-ONE" }, usesRemaining: { N: "4" } } });
ddb.on(TransactWriteItemsCommand).rejects(Object.assign(new Error("conflict"), { name: "TransactionCanceledException", CancellationReasons: [{ Code: "None" }, { Code: "TransactionConflict" }] }));
check("a transaction conflict is not read as a used code", (await thrown(() => handler(input({ registrationCode: "LCW-ONE" }))))?.name === "TransactionCanceledException");

console.log(failures ? `\n${failures} FAILED` : "\nall ok");
process.exit(failures ? 1 : 0);
