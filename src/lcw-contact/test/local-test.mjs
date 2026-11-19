// Local test for the lcw-contact handler: runs it in-process with a mocked
// DynamoDB and a fully signed zCap invocation for each request.
//
//   cd src/lcw-contact && npm install && npm test
import "@interop/http-client";
import { signCapabilityInvocation } from "@interop/http-signature-zcap-invoke";
import { Ed25519VerificationKey } from "@interop/ed25519-verification-key";
import { DynamoDBClient, GetItemCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import { mockClient } from "aws-sdk-client-mock";

const { handler } = await import("../index.mjs");

const HOST = "api.example.org";
const EMAIL = "test@example.com";

const key = await Ed25519VerificationKey.generate();
const did = `did:key:${key.fingerprint()}`;
key.id = `${did}#${key.fingerprint()}`;
key.controller = did;
const stranger = await Ed25519VerificationKey.generate();
stranger.controller = `did:key:${stranger.fingerprint()}`;
stranger.id = `${stranger.controller}#${stranger.fingerprint()}`;

const ddb = mockClient(DynamoDBClient);

// An in-memory accounts table; `extra` is merged into the account row
let accounts;
function reset({ registered = true, extra = {} } = {}) {
  ddb.reset();
  accounts = new Map(registered ? [[EMAIL, { email: { S: EMAIL }, did: { S: did }, CreatedAt: { S: "2026-11-01T00:00:00.000Z" }, ...extra }]] : []);
  ddb.on(GetItemCommand).callsFake(({ Key }) => ({ Item: accounts.get(Key.email.S) }));
  ddb.on(UpdateItemCommand).callsFake(({ Key, ExpressionAttributeValues: v }) => {
    const item = accounts.get(Key.email.S);
    item.contactOptIn = v[":choice"];
    item.contactOptInUpdatedAt = v[":at"];
    return {};
  });
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
const read = () => signed({ method: "GET", path: "/contact", query: `email=${encodeURIComponent(EMAIL)}` });
const write = (choice, signer) => signed({ method: "PUT", path: "/contact", json: { email: EMAIL, contactOptIn: choice }, ...(signer && { signer }) });

// -- reading the choice
reset();
let res = await handler(await read());
check("an account registered before the question reads as no", res.statusCode === 200 && JSON.parse(res.body).contactOptIn === false && JSON.parse(res.body).updatedAt === undefined);

reset({ extra: { contactOptIn: { BOOL: true }, contactOptInUpdatedAt: { S: "2026-11-18T00:00:00.000Z" } } });
res = await handler(await read());
check("an agreed account reads as yes, with when", res.statusCode === 200 && JSON.parse(res.body).contactOptIn === true && JSON.parse(res.body).updatedAt === "2026-11-18T00:00:00.000Z");

res = await handler(event({ method: "GET", path: "/contact", query: `email=${encodeURIComponent(EMAIL)}` }));
check("unsigned GET -> 401", res.statusCode === 401);

res = await handler(await signed({ method: "GET", path: "/contact", query: `email=${encodeURIComponent(EMAIL)}`, signer: stranger }));
check("GET signed by another key -> 401", res.statusCode === 401);

res = await handler(await signed({ method: "GET", path: "/contact" }));
check("GET without an email -> 400", res.statusCode === 400);

reset({ registered: false });
res = await handler(await read());
check("GET for an unregistered email -> 401", res.statusCode === 401);

// -- changing the choice
reset();
res = await handler(event({ method: "PUT", path: "/contact", body: JSON.stringify({ email: EMAIL, contactOptIn: true }) }));
check("unsigned PUT -> 401", res.statusCode === 401 && accounts.get(EMAIL).contactOptIn === undefined);

res = await handler(await write(true, stranger));
check("PUT signed by another key -> 401, nothing changed", res.statusCode === 401 && accounts.get(EMAIL).contactOptIn === undefined);

res = await handler(await signed({ method: "PUT", path: "/contact", json: { email: EMAIL, contactOptIn: "yes" } }));
check("PUT with a choice that is not true or false -> 400", res.statusCode === 400);

res = await handler(await write(true));
let row = accounts.get(EMAIL);
check("signed PUT records agreement", res.statusCode === 200 && JSON.parse(res.body).contactOptIn === true && row.contactOptIn.BOOL === true && Boolean(row.contactOptInUpdatedAt?.S));
const update = ddb.commandCalls(UpdateItemCommand)[0].args[0].input;
check("the update touches the two contact attributes of an existing row only",
  update.UpdateExpression === "SET contactOptIn = :choice, contactOptInUpdatedAt = :at" && update.ConditionExpression === "attribute_exists(email)" && update.ReturnValues === "NONE");
check("the account's did and creation time are untouched", row.did.S === did && row.CreatedAt.S === "2026-11-01T00:00:00.000Z");

res = await handler(await read());
check("the change reads back", res.statusCode === 200 && JSON.parse(res.body).contactOptIn === true);

res = await handler(await write(false));
check("signed PUT records a change of mind", res.statusCode === 200 && JSON.parse(res.body).contactOptIn === false && accounts.get(EMAIL).contactOptIn.BOOL === false);

// -- anything else
res = await handler(event({ method: "DELETE", path: "/contact" }));
check("unknown route -> 404", res.statusCode === 404);

console.log(failures ? `\n${failures} FAILED` : "\nall checks passed");
process.exit(failures ? 1 : 0);
