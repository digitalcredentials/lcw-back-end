// Local test for the lcw-login handler. Runs the handler in-process with a
// mocked DynamoDB table and prints the response for each scenario, including
// a fully signed zCap invocation that succeeds end to end.
//
//   cd src/lcw-login && npm install && npm test
import "@interop/http-client";
import { signCapabilityInvocation } from "@interop/http-signature-zcap-invoke";
import { Ed25519VerificationKey } from "@interop/ed25519-verification-key";
import { DynamoDBClient, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { mockClient } from "aws-sdk-client-mock";
import { handler } from "../index.mjs";
import { createDID, signerFromDidKeySigner, logToJsonlString } from "@interop/did-method-webvh";
import { clearWebvhCache } from "webvh-verify";

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

async function run(name, eventPromise, { registeredDid } = {}) {
    ddbMock.reset();
    // The account row: email -> did, plus the registration token the WAS
    // server's space-creation coupon is checked against.
    ddbMock.on(GetItemCommand).resolves(
        registeredDid
            ? { Item: { email: { S: EMAIL }, did: { S: registeredDid }, token: { S: "secret-code" } } }
            : {}
    );
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
const registered = await run("signed, matching DID -> 200", signedEvent({ email: EMAIL }), { registeredDid: did });
// Identity only: the controller and the token, no spaces (the wallet lists
// them through the PWS server).
const registeredBody = JSON.parse(registered.body);
const registeredOk = registered.statusCode === 200 &&
    registeredBody.controller === did &&
    registeredBody.token === "secret-code" &&
    registeredBody.space === undefined &&
    registeredBody.spaces === undefined;
console.log(`   controller + token, no spaces ${registeredOk ? "ok" : "FAIL"}`);


// An account registered as a did:webvh: the key signs under its verification
// method id in the account document, which the handler resolves from the
// log served at the DID's identity domain (fetch is stubbed here).
const multibase = key.fingerprint();
const minted = await createDID({
    address: "id.test",
    paths: ["space1"],
    signer: signerFromDidKeySigner(key.signer()),
    updateKeys: [did],
    verificationMethods: [{ type: "Multikey", publicKeyMultibase: multibase }],
    vmIdFragment: "multibase",
    authentication: [`#${multibase}`],
    assertionMethod: [`#${multibase}`],
    capabilityInvocation: [`#${multibase}`],
    capabilityDelegation: [`#${multibase}`]
});
const jsonl = logToJsonlString(minted.log);
const realFetch = globalThis.fetch;
globalThis.fetch = async (url) =>
    String(url) === "https://id.test/space1/did.jsonl"
        ? new Response(jsonl, { status: 200, headers: { "content-type": "text/jsonl" } })
        : new Response("not found", { status: 404 });
const inner = key.signer();
const accountSigner = { id: `${minted.did}#${multibase}`, algorithm: inner.algorithm, sign: inner.sign.bind(inner) };
async function accountSignedEvent({ email }, signer = accountSigner) {
    const json = { email };
    const headers = await signCapabilityInvocation({ url: URL, method: "POST", headers: { host: HOST }, json, capabilityAction: "write", invocationSigner: signer });
    return makeEvent({ body: JSON.stringify(json), headers });
}
clearWebvhCache();
const webvhLogin = await run("signed as the did:webvh's listed key -> 200", accountSignedEvent({ email: EMAIL }), { registeredDid: minted.did });
const webvhOk = webvhLogin.statusCode === 200 && JSON.parse(webvhLogin.body).controller === minted.did;
console.log(`   did:webvh account ${webvhOk ? "ok" : "FAIL"}`);
const stranger = await Ed25519VerificationKey.generate();
stranger.controller = `did:key:${stranger.fingerprint()}`;
stranger.id = `${stranger.controller}#${stranger.fingerprint()}`;
const strangerInner = stranger.signer();
const strangerSigner = { id: `${minted.did}#${stranger.fingerprint()}`, algorithm: strangerInner.algorithm, sign: strangerInner.sign.bind(strangerInner) };
const webvhStranger = await run("signed under the did:webvh by a key it does not list -> 401", accountSignedEvent({ email: EMAIL }, strangerSigner), { registeredDid: minted.did });
const strangerOk = webvhStranger.statusCode === 401;
console.log(`   unlisted key refused ${strangerOk ? "ok" : "FAIL"}`);
globalThis.fetch = realFetch;

process.exit(registeredOk && webvhOk && strangerOk ? 0 : 1);
