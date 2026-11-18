// Local test for the lcw-register handler: runs it in-process with a mocked
// Step Functions client and prints the response for each scenario.
//
//   cd src/lcw-register && npm install && npm test
import { SFNClient, StartExecutionCommand } from "@aws-sdk/client-sfn";
import { mockClient } from "aws-sdk-client-mock";

process.env.REGISTRATION_CODE = "test-registration-code";
process.env.STATE_MACHINE_ARN = "arn:aws:states:us-east-1:123456789012:stateMachine:wallet-account-creator";

const { handler } = await import("../index.mjs");
const sfnMock = mockClient(SFNClient);

const event = (body) => ({ isBase64Encoded: false, body });

async function run(name, body) {
    sfnMock.reset();
    sfnMock.on(StartExecutionCommand).resolves({ executionArn: "arn:aws:states:::execution/test" });
    const response = await handler(event(body));
    console.log(`\n== ${name}`);
    console.log(`   ${response.statusCode} ${response.body}`);
    console.log(`   executions started: ${sfnMock.commandCalls(StartExecutionCommand).length}`);
    return response;
}

await run("bad JSON body -> 400", "not json");
await run("missing fields -> 400", JSON.stringify({ email: "a@b.com" }));
await run("wrong code -> 403, no execution", JSON.stringify({
    email: "a@b.com", did: "did:key:z6MkTest", registrationCode: "nope"
}));
await run("missing code -> 403, no execution", JSON.stringify({
    email: "a@b.com", did: "did:key:z6MkTest"
}));
const ok = await run("valid code -> 202, execution started", JSON.stringify({
    email: "a@b.com", did: "did:key:z6MkTest", registrationCode: "test-registration-code"
}));

const started = sfnMock.commandCalls(StartExecutionCommand);
const input = JSON.parse(started[0].args[0].input.input);
console.log(`\n   execution input: ${JSON.stringify(input)}`);

// The contact choice rides to the account row: true only when ticked
const agreed = await run("ticked contact choice -> 202, passed on as true", JSON.stringify({
    email: "a@b.com", did: "did:key:z6MkTest", registrationCode: "test-registration-code", contactOptIn: true
}));
const agreedInput = JSON.parse(sfnMock.commandCalls(StartExecutionCommand)[0].args[0].input.input);
const odd = await run("a non-boolean contact choice -> passed on as false", JSON.stringify({
    email: "a@b.com", did: "did:key:z6MkTest", registrationCode: "test-registration-code", contactOptIn: "yes"
}));
const oddInput = JSON.parse(sfnMock.commandCalls(StartExecutionCommand)[0].args[0].input.input);
console.log(`\n   contact choice passed on: none -> ${input.contactOptIn}, true -> ${agreedInput.contactOptIn}, "yes" -> ${oddInput.contactOptIn}`);

process.exit(
    ok.statusCode === 202 && input.recipientEmail === "a@b.com" && input.did === "did:key:z6MkTest" &&
    input.contactOptIn === false && agreed.statusCode === 202 && agreedInput.contactOptIn === true &&
    odd.statusCode === 202 && oddInput.contactOptIn === false ? 0 : 1
);
