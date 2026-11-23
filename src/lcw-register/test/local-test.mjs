// Local test for the lcw-register handler: runs it in-process with a mocked
// Step Functions client and coupon table.
//
//   cd src/lcw-register && npm install && npm test
import { SFNClient, StartExecutionCommand } from "@aws-sdk/client-sfn";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { mockClient } from "aws-sdk-client-mock";

process.env.STATE_MACHINE_ARN = "arn:aws:states:us-east-1:123456789012:stateMachine:wallet-account-creator";
process.env.COUPONS_TABLE_NAME = "test-coupons";

const { handler } = await import("../index.mjs");
const sfnMock = mockClient(SFNClient);
const ddb = mockClient(DynamoDBClient);

const past = new Date(Date.now() - 60_000).toISOString();
const future = new Date(Date.now() + 60_000).toISOString();
const rows = {
    shared: { coupon: { S: "shared" } },
    limited: { coupon: { S: "limited" }, usesRemaining: { N: "4" }, expiresAt: { S: future } },
    "last-use": { coupon: { S: "last-use" }, usesRemaining: { N: "0" }, expiresAt: { S: future } },
    expired: { coupon: { S: "expired" }, usesRemaining: { N: "5" }, expiresAt: { S: past } },
    closed: { coupon: { S: "closed" }, usesRemaining: { N: "0" }, expiresAt: { S: future }, closedAt: { S: past } },
};

let failures = 0;
const check = (label, ok, detail) => {
    console.log(`${ok ? "ok  " : "FAIL"} ${label}${detail !== undefined ? ` (${JSON.stringify(detail)})` : ""}`);
    if (!ok) failures++;
};

async function run(body) {
    sfnMock.reset();
    ddb.reset();
    sfnMock.on(StartExecutionCommand).resolves({ executionArn: "arn:aws:states:::execution/test" });
    ddb.on(GetItemCommand).callsFake(({ TableName, Key }) => ({ Item: TableName === "test-coupons" ? rows[Key.coupon.S] : undefined }));
    const response = await handler({ isBase64Encoded: false, body: typeof body === "string" ? body : JSON.stringify(body) });
    const started = sfnMock.commandCalls(StartExecutionCommand);
    return { status: response.statusCode, started: started.length, input: started[0] && JSON.parse(started[0].args[0].input.input) };
}
const fields = (extra) => ({ email: "a@b.com", did: "did:key:z6MkTest", ...extra });

const badJson = await run("not json");
check("a body that is not JSON -> 400", badJson.status === 400 && badJson.started === 0);
const missing = await run({ email: "a@b.com" });
check("missing fields -> 400", missing.status === 400 && missing.started === 0);
for (const [label, code] of [["an unknown code", "nope"], ["no code", undefined], ["a code that is not a string", { S: "shared" }], ["an expired code", "expired"], ["a closed code", "closed"]]) {
    const refused = await run(fields({ registrationCode: code }));
    check(`${label} -> 403, no execution`, refused.status === 403 && refused.started === 0);
}

const shared = await run(fields({ registrationCode: "shared" }));
check("the shared code -> 202, execution started", shared.status === 202 && shared.started === 1 && shared.input.recipientEmail === "a@b.com" && shared.input.did === "did:key:z6MkTest");
check("the code is read consistently from the coupon table", ddb.commandCalls(GetItemCommand)[0].args[0].input.ConsistentRead === true);
const limited = await run(fields({ registrationCode: "limited" }));
check("a limited code -> 202", limited.status === 202 && limited.started === 1);
check("the code is passed on, so the account step can close it", limited.input.registrationCode === "limited");
// The PWS server takes this registration's use before the wallet calls here
const lastUse = await run(fields({ registrationCode: "last-use" }));
check("a code with no uses left that is not closed -> 202", lastUse.status === 202 && lastUse.started === 1);

// The contact choice is passed on to the account row: true only when ticked
const agreed = await run(fields({ registrationCode: "shared", contactOptIn: true }));
const odd = await run(fields({ registrationCode: "shared", contactOptIn: "yes" }));
check("the contact choice is passed on: none -> false, true -> true, \"yes\" -> false", shared.input.contactOptIn === false && agreed.input.contactOptIn === true && odd.input.contactOptIn === false);

sfnMock.reset();
ddb.reset();
ddb.on(GetItemCommand).rejects(new Error("table unavailable"));
const down = await handler({ isBase64Encoded: false, body: JSON.stringify(fields({ registrationCode: "shared" })) });
check("the coupon table unavailable -> 500, no execution", down.statusCode === 500 && sfnMock.commandCalls(StartExecutionCommand).length === 0);

console.log(failures ? `\n${failures} FAILED` : "\nall ok");
process.exit(failures ? 1 : 0);
