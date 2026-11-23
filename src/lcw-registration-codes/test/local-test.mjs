// Local test for the lcw-registration-codes handler: runs it in-process
// with a mocked Parameter Store and DynamoDB.
//
//   cd src/lcw-registration-codes && npm install && npm test
import { DynamoDBClient, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";
import { mockClient } from "aws-sdk-client-mock";

process.env.WALLET_URL = "https://wallet.example.org/";
process.env.CODE_ATTEMPTS = "5";
process.env.CODE_EXPIRY_DAYS = "90";
process.env.API_KEY_PARAMETER = "/test/api-key";

const { handler } = await import("../index.mjs");
const ddb = mockClient(DynamoDBClient);
const ssm = mockClient(SSMClient);
ssm.on(GetParameterCommand).resolves({ Parameter: { Value: "the-key" } });
ddb.on(PutItemCommand).resolves({});

let failures = 0;
const check = (label, ok, detail) => {
    console.log(`${ok ? "ok  " : "FAIL"} ${label}${detail !== undefined ? ` (${JSON.stringify(detail)})` : ""}`);
    if (!ok) failures++;
};
const event = ({ key, body }) => ({ isBase64Encoded: false, headers: key === undefined ? {} : { "X-Api-Key": key }, body });
const puts = () => ddb.commandCalls(PutItemCommand);

const none = await handler(event({}));
check("no key -> 401, nothing written", none.statusCode === 401 && puts().length === 0);
const wrong = await handler(event({ key: "another-key" }));
check("a wrong key -> 401, nothing written", wrong.statusCode === 401 && puts().length === 0);
const bad = await handler(event({ key: "the-key", body: "not json" }));
check("a body that is not JSON -> 400", bad.statusCode === 400 && puts().length === 0);
const long = await handler(event({ key: "the-key", body: JSON.stringify({ issuedTo: "x".repeat(321) }) }));
check("an over-long issuedTo -> 400", long.statusCode === 400 && puts().length === 0);

const before = Date.now();
const made = await handler(event({ key: "the-key", body: JSON.stringify({ issuedTo: "applicant@example.com" }) }));
const answer = JSON.parse(made.body);
const item = puts()[0]?.args[0].input.Item;
check("the right key -> 201 with a code", made.statusCode === 201 && /^LCW-[2-9A-HJKMNP-Z]{16}$/.test(answer.code), answer.code?.length);
check("the link opens the wallet's registration page with the code", answer.link === `https://wallet.example.org/#/register?code=${answer.code}`, answer.link?.replace(answer.code, "<code>"));
const days = (Date.parse(answer.expiresAt) - before) / 86_400_000;
check("the code expires in 90 days", days >= 90 && days < 90.01, days);
check("the row is the code, with its attempts, expiry and who it is for", item.coupon.S === answer.code && item.usesRemaining.N === "5" && item.expiresAt.S === answer.expiresAt && item.issuedTo.S === "applicant@example.com" && Boolean(item.issuedAt.S));
check("the write refuses to replace an existing code", puts()[0].args[0].input.ConditionExpression === "attribute_not_exists(coupon)");
check("the row is not closed", item.closedAt === undefined);

ddb.resetHistory();
const bare = await handler(event({ key: "the-key" }));
const bareItem = puts()[0]?.args[0].input.Item;
check("no body -> 201, a row with no issuedTo", bare.statusCode === 201 && bareItem.issuedTo === undefined);
check("two codes differ", JSON.parse(bare.body).code !== answer.code);
check("the key was read from the named parameter, decrypted", ssm.commandCalls(GetParameterCommand).every((call) => call.args[0].input.Name === "/test/api-key" && call.args[0].input.WithDecryption === true));
check("the key was read once and kept", ssm.commandCalls(GetParameterCommand).length === 1);

ddb.on(PutItemCommand).rejects(new Error("table unavailable"));
const failed = await handler(event({ key: "the-key" }));
check("a failed write -> 500, no code answered", failed.statusCode === 500 && !JSON.parse(failed.body).code);

console.log(failures ? `\n${failures} FAILED` : "\nall ok");
process.exit(failures ? 1 : 0);
