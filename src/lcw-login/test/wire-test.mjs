// End-to-end wire test: signs a zCap invocation the same way the front end
// will (key derived from SHA-256 of a password) and POSTs it over HTTP to the
// sam local API, against a temporary account in the real wallet-test table.
// Usage: node test/wire-test.mjs (needs the sam local API on :3001 and AWS creds).
import { createHash } from "node:crypto";
import "@interop/http-client";
import { signCapabilityInvocation } from "@interop/http-signature-zcap-invoke";
import { Ed25519VerificationKey } from "@interop/ed25519-verification-key";
import { DynamoDBClient, PutItemCommand, DeleteItemCommand } from "@aws-sdk/client-dynamodb";

const API = "http://127.0.0.1:3001/login";
const EMAIL = "wire-test@example.com";
const PASSWORD = "correct horse battery staple";
const SPACE_URL = "https://was.example.org/space/dcc-was-wire-test";

// Same derivation the front end uses: SHA-256(password) as the Ed25519 seed
const seed = new Uint8Array(createHash("sha256").update(PASSWORD).digest());
const key = await Ed25519VerificationKey.generate({ seed });
key.controller = `did:key:${key.fingerprint()}`;
key.id = `${key.controller}#${key.fingerprint()}`;
console.log("derived controller:", key.controller);

const ddb = new DynamoDBClient({ region: "us-east-1" });
await ddb.send(new PutItemCommand({
    TableName: "wallet-test",
    Item: {
        email: { S: EMAIL },
        did: { S: key.controller },
        spaceURL: { S: SPACE_URL },
        CreatedAt: { S: new Date().toISOString() }
    }
}));
console.log("temp account registered in wallet-test");

try {
    const json = { email: EMAIL };
    const headers = await signCapabilityInvocation({
        url: API,
        method: "POST",
        headers: { date: new Date().toUTCString() },
        json,
        capabilityAction: "write",
        invocationSigner: key.signer()
    });

    const res = await fetch(API, {
        method: "POST",
        headers,
        body: JSON.stringify(json)
    });
    const body = await res.text();
    console.log(`signed login over the wire -> ${res.status} ${body}`);

    // Wrong password: different derived key must be rejected
    const badSeed = new Uint8Array(createHash("sha256").update("wrong password").digest());
    const badKey = await Ed25519VerificationKey.generate({ seed: badSeed });
    badKey.controller = `did:key:${badKey.fingerprint()}`;
    badKey.id = `${badKey.controller}#${badKey.fingerprint()}`;
    const badHeaders = await signCapabilityInvocation({
        url: API,
        method: "POST",
        headers: { date: new Date().toUTCString() },
        json,
        capabilityAction: "write",
        invocationSigner: badKey.signer()
    });
    const badRes = await fetch(API, { method: "POST", headers: badHeaders, body: JSON.stringify(json) });
    console.log(`wrong-password login over the wire -> ${badRes.status} ${await badRes.text()}`);

    process.exit(res.status === 200 && badRes.status === 401 ? 0 : 1);
} finally {
    await ddb.send(new DeleteItemCommand({
        TableName: "wallet-test",
        Key: { email: { S: EMAIL } }
    }));
    console.log("temp account removed");
}
