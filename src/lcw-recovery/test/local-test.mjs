// Local test for the lcw-recovery handler: runs it in-process with mocked
// DynamoDB, KMS and SES, and a fully signed zCap invocation for the account
// routes.
//
//   cd src/lcw-recovery && npm install && npm test
import "@interop/http-client";
import { signCapabilityInvocation } from "@interop/http-signature-zcap-invoke";
import { Ed25519VerificationKey } from "@interop/ed25519-verification-key";
import { DynamoDBClient, GetItemCommand, PutItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { KMSClient, EncryptCommand, DecryptCommand } from "@aws-sdk/client-kms";
import { SESv2Client, SendEmailCommand } from "@aws-sdk/client-sesv2";
import { mockClient } from "aws-sdk-client-mock";

process.env.RECOVERY_KEY_ID = "key-1";
process.env.FROM_EMAIL = "wallet@example.org";
process.env.ORG_NAME = "Example Org";
process.env.WALLET_URL = "https://wallet.example.org";
process.env.MAX_SENDS = "2";
const { handler } = await import("../index.mjs");

const HOST = "api.example.org";
const EMAIL = "test@example.com";
const CODE = "ABCD-EFGH-IJKL";

const key = await Ed25519VerificationKey.generate();
const did = `did:key:${key.fingerprint()}`;
key.id = `${did}#${key.fingerprint()}`;
key.controller = did;
const stranger = await Ed25519VerificationKey.generate();
stranger.controller = `did:key:${stranger.fingerprint()}`;
stranger.id = `${stranger.controller}#${stranger.fingerprint()}`;

const ddb = mockClient(DynamoDBClient);
const kms = mockClient(KMSClient);
const ses = mockClient(SESv2Client);

// In-memory tables
let accounts, recovery;
function reset({ registered = true, stored = false } = {}) {
  ddb.reset(); kms.reset(); ses.reset();
  accounts = new Map(registered ? [[EMAIL, { email: { S: EMAIL }, did: { S: did } }]] : []);
  recovery = new Map();
  if (stored) {
    recovery.set(EMAIL, { email: { S: EMAIL }, code: { B: Buffer.from(`enc:${CODE}`) }, windowStart: { N: "0" }, sends: { N: "0" } });
  }
  ddb.on(GetItemCommand).callsFake(({ TableName, Key }) =>
    ({ Item: (TableName === "wallet-test" ? accounts : recovery).get(Key.email.S) }));
  ddb.on(PutItemCommand).callsFake(({ Item }) => { recovery.set(Item.email.S, Item); return {}; });
  ddb.on(UpdateItemCommand).callsFake(({ Key, ExpressionAttributeValues: v }) => {
    const item = recovery.get(Key.email.S);
    item.windowStart = v[":start"]; item.sends = v[":sends"];
    return {};
  });
  kms.on(EncryptCommand).callsFake(({ Plaintext }) => ({ CiphertextBlob: Buffer.concat([Buffer.from("enc:"), Buffer.from(Plaintext)]) }));
  kms.on(DecryptCommand).callsFake(({ CiphertextBlob }) => ({ Plaintext: Buffer.from(CiphertextBlob).subarray(4) }));
  ses.on(SendEmailCommand).resolves({ MessageId: "m" });
}

const event = ({ method, path, query = "", body, headers = {} }) => ({
  rawPath: path,
  rawQueryString: query,
  isBase64Encoded: false,
  headers,
  body,
  queryStringParameters: query ? Object.fromEntries(new URLSearchParams(query)) : undefined,
  requestContext: { domainName: HOST, http: { method } },
});

async function signed({ method, path, query = "", json, signer = key }) {
  const url = `https://${HOST}${path}${query ? `?${query}` : ""}`;
  const headers = await signCapabilityInvocation({
    url, method, headers: { host: HOST }, ...(json && { json }),
    capabilityAction: method === "GET" ? "read" : "write",
    invocationSigner: signer.signer(),
  });
  return event({ method, path, query, body: json && JSON.stringify(json), headers });
}

let failures = 0;
const check = (name, ok, detail) => {
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? ` - ${detail}` : ""}`);
  if (!ok) failures++;
};

// -- storing and checking the code
reset();
let res = await handler(event({ method: "PUT", path: "/recovery", body: JSON.stringify({ email: EMAIL, code: CODE }) }));
check("unsigned PUT -> 401", res.statusCode === 401);

reset();
res = await handler(await signed({ method: "PUT", path: "/recovery", json: { email: EMAIL, code: CODE }, signer: stranger }));
check("PUT signed by another key -> 401", res.statusCode === 401 && recovery.size === 0);

reset({ registered: false });
res = await handler(await signed({ method: "PUT", path: "/recovery", json: { email: EMAIL, code: CODE } }));
check("PUT for an unregistered email -> 401", res.statusCode === 401);

reset();
res = await handler(await signed({ method: "PUT", path: "/recovery", json: { email: EMAIL } }));
check("PUT without a code -> 400", res.statusCode === 400);

reset();
res = await handler(await signed({ method: "PUT", path: "/recovery", json: { email: EMAIL, code: CODE } }));
const row = recovery.get(EMAIL);
check("signed PUT stores the code", res.statusCode === 204 && Boolean(row));
check("the stored code is not plaintext (KMS ciphertext)", Buffer.from(row.code.B).subarray(0, 4).toString() === "enc:");

res = await handler(await signed({ method: "GET", path: "/recovery", query: `email=${encodeURIComponent(EMAIL)}` }));
check("GET reports a stored code", res.statusCode === 200 && JSON.parse(res.body).stored === true);

reset();
res = await handler(await signed({ method: "GET", path: "/recovery", query: `email=${encodeURIComponent(EMAIL)}` }));
check("GET reports no code before one is stored", res.statusCode === 200 && JSON.parse(res.body).stored === false);

res = await handler(event({ method: "GET", path: "/recovery", query: `email=${encodeURIComponent(EMAIL)}` }));
check("unsigned GET -> 401", res.statusCode === 401);

// -- forgot
const forgot = (email) => handler(event({ method: "POST", path: "/forgot", body: JSON.stringify({ email }) }));

reset({ stored: true });
res = await forgot(EMAIL);
let sends = ses.commandCalls(SendEmailCommand);
check("forgot mails the code to the registered address", res.statusCode === 202 && sends.length === 1 &&
  sends[0].args[0].input.Destination.ToAddresses[0] === EMAIL &&
  sends[0].args[0].input.Content.Simple.Body.Text.Data.includes(CODE) &&
  sends[0].args[0].input.Content.Simple.Body.Html.Data.includes(CODE));
const answered = res.body;

reset({ registered: false });
res = await forgot("nobody@example.com");
check("forgot for an unknown address sends nothing and answers the same", res.statusCode === 202 && res.body === answered && ses.commandCalls(SendEmailCommand).length === 0);

reset();
res = await forgot(EMAIL);
check("forgot for an account with no code sends nothing and answers the same", res.statusCode === 202 && res.body === answered && ses.commandCalls(SendEmailCommand).length === 0);

reset({ stored: true });
await forgot(EMAIL); await forgot(EMAIL); res = await forgot(EMAIL);
check("forgot is rate limited (2 sends in the window, the third answers the same)",
  res.statusCode === 202 && res.body === answered && ses.commandCalls(SendEmailCommand).length === 2);

res = await handler(event({ method: "POST", path: "/forgot", body: "not json" }));
check("forgot with a bad body -> 400", res.statusCode === 400);

res = await handler(event({ method: "POST", path: "/other", body: "{}" }));
check("unknown route -> 404", res.statusCode === 404);

console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
