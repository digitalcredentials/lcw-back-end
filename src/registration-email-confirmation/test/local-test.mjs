// Local test for the confirmation handler: the confirmation page and the
// status route, with Step Functions and DynamoDB mocked.
//
//   cd src/registration-email-confirmation && npm install && npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { SFNClient, SendTaskSuccessCommand } from "@aws-sdk/client-sfn";
import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";
import { mockClient } from "aws-sdk-client-mock";
import { confirmationKeyOf, handler } from "../index.mjs";

const sfnMock = mockClient(SFNClient);
const ddbMock = mockClient(DynamoDBClient);
const TOKEN = "AAAAKgAAAAIAAAAAAAAAAbcd+efg/hij=";
const KEY = confirmationKeyOf(TOKEN);

const confirmEvent = (rawQueryString) => ({ rawPath: "/confirm", rawQueryString });
const statusEvent = (key) => ({ rawPath: "/confirm/status", queryStringParameters: key === undefined ? undefined : { key } });

test("the confirmation key is the token's SHA-256", () => {
  assert.match(KEY, /^[0-9a-f]{64}$/);
  assert.notEqual(KEY, confirmationKeyOf(`${TOKEN}x`));
});

test("a link without a token is refused", async () => {
  const res = await handler(confirmEvent(""));
  assert.equal(res.statusCode, 400);
  assert.match(res.body, /missing its token/);
});

test("a token the state machine refuses shows the already-confirmed page, with the button", async () => {
  sfnMock.reset();
  sfnMock.on(SendTaskSuccessCommand).rejects(new Error("TaskTimedOut"));
  const res = await handler(confirmEvent(`token=${encodeURIComponent(TOKEN)}`));
  assert.equal(res.statusCode, 400);
  assert.match(res.body, /no longer works/);
  assert.match(res.body, /Open my wallet/);
});

test("an accepted token hands the key to the state machine and shows the waiting page", async () => {
  sfnMock.reset();
  sfnMock.on(SendTaskSuccessCommand).resolves({});
  const res = await handler(confirmEvent(`token=${encodeURIComponent(TOKEN)}`));
  assert.equal(res.statusCode, 200);
  const sent = sfnMock.commandCalls(SendTaskSuccessCommand)[0].args[0].input;
  assert.equal(sent.taskToken, TOKEN);
  assert.deepEqual(JSON.parse(sent.output), { confirmationStatus: "VERIFIED", confirmationKey: KEY });
  // The page waits: the button is only in the no-script fallback and the
  // ready text the script swaps in, and the page polls the status route
  assert.match(res.body, /Hang tight, we are setting up your wallet/);
  assert.match(res.body, new RegExp(`/confirm/status\\?key=${KEY}`));
  const visible = res.body.replace(/<noscript>[\s\S]*?<\/noscript>/, "").replace(/<script>[\s\S]*?<\/script>/, "");
  assert.doesNotMatch(visible, /Open my wallet/);
  assert.equal(res.headers["Cache-Control"], "no-store");
});

test("the status route refuses a malformed key", async () => {
  for (const key of [undefined, "", "abc", `${KEY}0`, KEY.toUpperCase()]) {
    const res = await handler(statusEvent(key));
    assert.equal(res.statusCode, 400, `key ${JSON.stringify(key)}`);
  }
});

test("the status route reports the account once its row is there", async () => {
  ddbMock.reset();
  ddbMock.on(QueryCommand).resolves({ Count: 0 });
  let res = await handler(statusEvent(KEY));
  assert.equal(res.statusCode, 200);
  assert.deepEqual(JSON.parse(res.body), { ready: false });
  const query = ddbMock.commandCalls(QueryCommand)[0].args[0].input;
  assert.equal(query.IndexName, "confirmationKey-index");
  assert.deepEqual(query.ExpressionAttributeValues, { ":key": { S: KEY } });

  ddbMock.on(QueryCommand).resolves({ Count: 1 });
  res = await handler(statusEvent(KEY));
  assert.deepEqual(JSON.parse(res.body), { ready: true });
  assert.equal(res.headers["Cache-Control"], "no-store");
});

test("a failed lookup is a server error, not a false 'not yet'", async () => {
  ddbMock.reset();
  ddbMock.on(QueryCommand).rejects(new Error("ProvisionedThroughputExceededException"));
  const res = await handler(statusEvent(KEY));
  assert.equal(res.statusCode, 500);
});
