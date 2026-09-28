// Local test for the lcw-login handler. Runs the handler in-process with a
// mocked DynamoDB table and prints the response for each scenario, including
// a fully signed zCap invocation that succeeds end to end.
//
//   cd src/lcw-login && npm install && npm test
import "@interop/http-client";
import { signCapabilityInvocation } from "@interop/http-signature-zcap-invoke";
import { Ed25519VerificationKey } from "@interop/ed25519-verification-key";
import { DynamoDBClient, GetItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { mockClient } from "aws-sdk-client-mock";
import { handler } from "../index.mjs";

const HOST = "iibe16rs13.execute-api.us-east-1.amazonaws.com";
const URL = `https://${HOST}/login`;
const EMAIL = "test@example.com";
const SPACE_URL = "https://was.example.org/space/dcc-was-11111111-2222-3333-4444-555555555555";

// A did:key whose private key we hold, standing in for the wallet's key
const key = await Ed25519VerificationKey.generate();
const did = `did:key:${key.fingerprint()}`;
key.id = `${did}#${key.fingerprint()}`;
key.controller = did;

const ddbMock = mockClient(DynamoDBClient);

const makeEvent = ({ body, headers = {} }) => ({
    rawPath: "/login",
    isBase64Encoded: false,
    headers,
    body,
    requestContext: { domainName: HOST, http: { method: "POST" } }
});

async function signedEvent({ email }) {
    const json = { email };
    const headers = await signCapabilityInvocation({
        url: URL,
        method: "POST",
        headers: { host: HOST },
        json,
        capabilityAction: "write",
        invocationSigner: key.signer()
    });
    return makeEvent({ body: JSON.stringify(json), headers });
}

async function run(name, eventPromise, { registeredDid, spaceItems } = {}) {
    ddbMock.reset();
    ddbMock.on(GetItemCommand).resolves(
        registeredDid
            ? { Item: { email: { S: EMAIL }, did: { S: registeredDid }, spaceURL: { S: SPACE_URL } } }
            : {}
    );
    // The wallet-spaces registry; empty for legacy accounts.
    ddbMock.on(QueryCommand).resolves({ Items: spaceItems ?? [] });
    const response = await handler(await eventPromise);
    console.log(`\n== ${name}`);
    console.log(`   ${response.statusCode} ${response.body}`);
    return response;
}

console.log(`Signing key controller: ${did}`);

await run("bad JSON body -> 400", makeEvent({ body: "not json" }));
await run("missing email -> 400", makeEvent({ body: "{}" }));
await run("unsigned request -> 401", makeEvent({ body: JSON.stringify({ email: EMAIL }) }), {
    registeredDid: did
});
await run("signed, email not registered -> 401", signedEvent({ email: EMAIL }));
await run("signed, different DID registered -> 401", signedEvent({ email: EMAIL }), {
    registeredDid: "did:key:z6MkfDLjE5Kip9E7YRitEbrNAcCYi2AviAY8Ny7hoYnCSgav"
});
const legacy = await run("signed, matching DID, legacy account -> 200", signedEvent({ email: EMAIL }), {
    registeredDid: did
});
// No registry rows: the single legacy spaceURL comes back as the credential space.
const legacySpaces = JSON.parse(legacy.body).spaces;
const legacyOk = legacy.statusCode === 200 &&
    legacySpaces.length === 1 &&
    legacySpaces[0].url === SPACE_URL &&
    legacySpaces[0].type === "credential";
console.log(`   spaces fallback ${legacyOk ? "ok" : "FAIL"}`);

const registered = await run("signed, matching DID, registry rows -> 200", signedEvent({ email: EMAIL }), {
    registeredDid: did,
    spaceItems: [
        { spaceURL: { S: SPACE_URL }, type: { S: "credential" }, name: { S: "Wallet space" } },
        { spaceURL: { S: `${SPACE_URL}-batch` }, type: { S: "batch" }, name: { S: "Conference 2026" } }
    ]
});
const registeredSpaces = JSON.parse(registered.body).spaces;
const registeredOk = registered.statusCode === 200 &&
    registeredSpaces.length === 2 &&
    registeredSpaces.some(({ type, name }) => type === "batch" && name === "Conference 2026");
console.log(`   spaces registry ${registeredOk ? "ok" : "FAIL"}`);

process.exit(legacyOk && registeredOk ? 0 : 1);
