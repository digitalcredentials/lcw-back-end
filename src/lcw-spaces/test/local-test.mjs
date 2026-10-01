// Local test for the lcw-spaces handler. Runs the handler in-process with
// mocked DynamoDB and S3 clients and prints the response for each scenario,
// including fully signed zCap invocations that succeed end to end.
//
//   cd src/lcw-spaces && npm install && npm test
import "@interop/http-client";
import { signCapabilityInvocation } from "@interop/http-signature-zcap-invoke";
import { Ed25519VerificationKey } from "@interop/ed25519-verification-key";
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
import { mockClient } from "aws-sdk-client-mock";
import { handler } from "../index.mjs";

const HOST = "iibe16rs13.execute-api.us-east-1.amazonaws.com";
const EMAIL = "test@example.com";
const SPACES_TABLE = "wallet-spaces";
const BATCH_SPACE_URL = "https://was.example.org/space/dcc-was-11111111-2222-3333-4444-555555555555";

// A did:key whose private key we hold, standing in for the wallet's key
const key = await Ed25519VerificationKey.generate();
const did = `did:key:${key.fingerprint()}`;
key.id = `${did}#${key.fingerprint()}`;
key.controller = did;

const ddbMock = mockClient(DynamoDBClient);
const s3Mock = mockClient(S3Client);

const makeEvent = ({ method, rawPath = "/spaces", rawQueryString = "", body, headers = {} }) => ({
    rawPath,
    rawQueryString,
    queryStringParameters: Object.fromEntries(new URLSearchParams(rawQueryString)),
    isBase64Encoded: false,
    headers,
    body,
    requestContext: { domainName: HOST, http: { method } }
});

async function signedEvent({ method, rawQueryString = "", json }) {
    const url = `https://${HOST}/spaces${rawQueryString ? `?${rawQueryString}` : ""}`;
    const headers = await signCapabilityInvocation({
        url,
        method,
        headers: { host: HOST },
        ...(json && { json }),
        capabilityAction: method === "GET" ? "read" : "write",
        invocationSigner: key.signer()
    });
    return makeEvent({
        method,
        rawQueryString,
        body: json ? JSON.stringify(json) : undefined,
        headers
    });
}

let failures = 0;

function resetMocks({ registeredDid, spaceItem } = {}) {
    ddbMock.reset();
    s3Mock.reset();
    ddbMock.on(GetItemCommand, { TableName: "wallet-test" }).resolves(
        registeredDid ? { Item: { email: { S: EMAIL }, did: { S: registeredDid } } } : {}
    );
    ddbMock.on(GetItemCommand, { TableName: SPACES_TABLE }).resolves(
        spaceItem ? { Item: spaceItem } : {}
    );
    ddbMock.on(QueryCommand).resolves({
        Items: [
            {
                spaceURL: { S: "https://was.example.org/space/dcc-was-wallet" },
                email: { S: EMAIL },
                type: { S: "credential" },
                name: { S: "Wallet space" },
                CreatedAt: { S: "2026-01-01T00:00:00Z" }
            },
            {
                spaceURL: { S: BATCH_SPACE_URL },
                email: { S: EMAIL },
                type: { S: "batch" },
                name: { S: "Conference 2026" },
                CreatedAt: { S: "2026-02-01T00:00:00Z" }
            }
        ]
    });
    ddbMock.on(PutItemCommand).resolves({});
    ddbMock.on(DeleteItemCommand).resolves({});
    s3Mock.on(CreateBucketCommand).resolves({});
    s3Mock.on(PutObjectCommand).resolves({});
    s3Mock.on(ListObjectsV2Command).resolves({
        Contents: [{ Key: "metadata/description.json" }, { Key: "batch/batch.json" }]
    });
    s3Mock.on(DeleteObjectsCommand).resolves({});
    s3Mock.on(DeleteBucketCommand).resolves({});
}

async function run(name, eventPromise, { expect, mocks } = {}) {
    resetMocks(mocks);
    const response = await handler(await eventPromise);
    const ok = response.statusCode === expect;
    if (!ok) failures++;
    console.log(`\n${ok ? "ok  " : "FAIL"} ${name}`);
    console.log(`     ${response.statusCode} ${response.body}`);
    return response;
}

console.log(`Signing key controller: ${did}`);

await run("POST bad JSON body -> 400",
    makeEvent({ method: "POST", body: "not json" }), { expect: 400 });

await run("POST missing email -> 400",
    makeEvent({ method: "POST", body: "{}" }), { expect: 400 });

await run("POST unsigned -> 401",
    makeEvent({ method: "POST", body: JSON.stringify({ email: EMAIL, type: "batch" }) }),
    { expect: 401, mocks: { registeredDid: did } });

await run("POST signed, email not registered -> 401",
    signedEvent({ method: "POST", json: { email: EMAIL, type: "batch" } }),
    { expect: 401 });

await run("POST signed, bad type -> 400",
    signedEvent({ method: "POST", json: { email: EMAIL, type: "nope" } }),
    { expect: 400, mocks: { registeredDid: did } });

const created = await run("POST signed, matching DID -> 201",
    signedEvent({ method: "POST", json: { email: EMAIL, type: "batch", name: "Conference 2026" } }),
    { expect: 201, mocks: { registeredDid: did } });
{
    const body = JSON.parse(created.body);
    const bucketCalls = s3Mock.commandCalls(CreateBucketCommand);
    const putItemCalls = ddbMock.commandCalls(PutItemCommand);
    const item = putItemCalls[0]?.args[0]?.input?.Item;
    const ok =
        /^https:\/\/was\.example\.org\/space\/dcc-was-[0-9a-f-]{36}$/.test(body.space) &&
        body.type === "batch" &&
        body.name === "Conference 2026" &&
        bucketCalls.length === 1 &&
        item?.type?.S === "batch" &&
        item?.did?.S === did &&
        item?.name === undefined &&
        item?.spaceURL?.S === body.space;
    if (!ok) failures++;
    console.log(`${ok ? "ok  " : "FAIL"} POST created bucket + registered typed space row`);
}

const listed = await run("GET signed -> 200",
    signedEvent({ method: "GET", rawQueryString: `email=${encodeURIComponent(EMAIL)}` }),
    { expect: 200, mocks: { registeredDid: did } });
{
    const { spaces } = JSON.parse(listed.body);
    // Display names live in the WAS description documents, not the registry
    const ok = spaces.length === 2 &&
        spaces.some(({ type }) => type === "credential") &&
        spaces.some(({ type }) => type === "batch") &&
        spaces.every((space) => !("name" in space));
    if (!ok) failures++;
    console.log(`${ok ? "ok  " : "FAIL"} GET returns both typed spaces without names`);
}

await run("DELETE signed, batch space -> 204",
    signedEvent({
        method: "DELETE",
        rawQueryString: `email=${encodeURIComponent(EMAIL)}&space=${encodeURIComponent(BATCH_SPACE_URL)}`
    }),
    {
        expect: 204,
        mocks: {
            registeredDid: did,
            spaceItem: { spaceURL: { S: BATCH_SPACE_URL }, email: { S: EMAIL }, type: { S: "batch" } }
        }
    });
{
    const ok = s3Mock.commandCalls(DeleteBucketCommand).length === 1 &&
        ddbMock.commandCalls(DeleteItemCommand).length === 1;
    if (!ok) failures++;
    console.log(`${ok ? "ok  " : "FAIL"} DELETE emptied + deleted bucket and registry row`);
}

await run("DELETE signed, credential space -> 403",
    signedEvent({
        method: "DELETE",
        rawQueryString: `email=${encodeURIComponent(EMAIL)}&space=${encodeURIComponent(BATCH_SPACE_URL)}`
    }),
    {
        expect: 403,
        mocks: {
            registeredDid: did,
            spaceItem: { spaceURL: { S: BATCH_SPACE_URL }, email: { S: EMAIL }, type: { S: "credential" } }
        }
    });

await run("DELETE signed, another account's space -> 404",
    signedEvent({
        method: "DELETE",
        rawQueryString: `email=${encodeURIComponent(EMAIL)}&space=${encodeURIComponent(BATCH_SPACE_URL)}`
    }),
    {
        expect: 404,
        mocks: {
            registeredDid: did,
            spaceItem: { spaceURL: { S: BATCH_SPACE_URL }, email: { S: "other@example.com" }, type: { S: "batch" } }
        }
    });

console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
