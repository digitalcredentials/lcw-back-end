// Local test for the lcw-badge handler: runs it in-process with a mocked
// DynamoDB and a fully signed zCap invocation for the signed route.
//
//   cd src/lcw-badge && npm install && npm test
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

// An in-memory accounts table that applies the handler's two updates under
// their conditions
let accounts;
function reset({ registered = true, extra = {} } = {}) {
  ddb.reset();
  accounts = new Map(registered ? [[EMAIL, { email: { S: EMAIL }, did: { S: did }, CreatedAt: { S: "2026-11-01T00:00:00.000Z" }, ...extra }]] : []);
  ddb.on(GetItemCommand).callsFake(({ Key }) => ({ Item: accounts.get(Key.email.S) }));
  ddb.on(UpdateItemCommand).callsFake(({ Key, UpdateExpression, ExpressionAttributeValues: v }) => {
    const item = accounts.get(Key.email.S);
    const refuse = () => { throw Object.assign(new Error("condition"), { name: "ConditionalCheckFailedException" }); };
    if (!item) refuse();
    if (UpdateExpression.includes("badgeCollections")) {
      const count = Number(item.badgeCollections?.N ?? "0");
      if (item.badgeGrant?.S !== v[":secret"].S || count >= Number(v[":max"].N)) refuse();
      item.badgeCollections = { N: String(count + 1) };
      item.badgeCollectedAt = v[":at"];
    } else {
      item.badgeGrant ??= v[":secret"];
    }
    return {};
  });
}

const event = ({ method, path, body, headers = {} }) => ({
  rawPath: path, rawQueryString: "", isBase64Encoded: false, headers, body,
  requestContext: { domainName: HOST, http: { method } },
});

async function signed({ path, json, signer = key }) {
  const headers = await signCapabilityInvocation({
    url: `https://${HOST}${path}`, method: "POST", headers: { host: HOST }, json,
    capabilityAction: "write", invocationSigner: signer.signer(),
  });
  return event({ method: "POST", path, body: JSON.stringify(json), headers });
}

let failures = 0;
const check = (name, ok, detail) => {
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? ` - ${detail}` : ""}`);
  if (!ok) failures++;
};
const ask = (signer) => signed({ path: "/badge-grant", json: { email: EMAIL }, ...(signer && { signer }) });
const redeem = (body) => handler(event({ method: "POST", path: "/badge-grant/redeem", body: JSON.stringify(body) }));
const bodyOf = (res) => JSON.parse(res.body);

// -- asking for the grant
reset();
let res = await handler(event({ method: "POST", path: "/badge-grant", body: JSON.stringify({ email: EMAIL }) }));
check("unsigned request -> 401, nothing stored", res.statusCode === 401 && accounts.get(EMAIL).badgeGrant === undefined);
res = await handler(await ask(stranger));
check("request signed by another key -> 401, nothing stored", res.statusCode === 401 && accounts.get(EMAIL).badgeGrant === undefined);
res = await handler(await signed({ path: "/badge-grant", json: {} }));
check("request without an email -> 400", res.statusCode === 400);

res = await handler(await ask());
const grant = bodyOf(res).grant;
check("the account's signed request gets a grant", res.statusCode === 200 && typeof grant === "string" && grant.split(".").length === 2);
check("the grant's secret is stored on the account row", accounts.get(EMAIL).badgeGrant?.S === grant.split(".")[1]);
res = await handler(await ask());
check("a second request gets the same grant", res.statusCode === 200 && bodyOf(res).grant === grant);
const first = ddb.commandCalls(UpdateItemCommand)[0].args[0].input;
check("the update sets the grant on an existing row only, and never replaces one",
  first.UpdateExpression === "SET badgeGrant = if_not_exists(badgeGrant, :secret)" && first.ConditionExpression === "attribute_exists(email)" && first.ReturnValues === "NONE");
check("the account's did and creation time are untouched", accounts.get(EMAIL).did.S === did && accounts.get(EMAIL).CreatedAt.S === "2026-11-01T00:00:00.000Z");

reset({ registered: false });
res = await handler(await ask());
check("request for an unregistered email -> 401", res.statusCode === 401);

// -- the issuer's side
reset();
const good = bodyOf(await handler(await ask())).grant;
res = await redeem({ grant: good });
check("a good grant checks as valid, and stays unused", res.statusCode === 200 && bodyOf(res).valid === true && accounts.get(EMAIL).badgeCollectedAt === undefined);
res = await redeem({ grant: `${good.split(".")[0]}.not-the-secret` });
check("a wrong secret -> 404", res.statusCode === 404 && bodyOf(res).valid === false);
res = await redeem({ grant: `${Buffer.from("nobody@example.com").toString("base64url")}.${good.split(".")[1]}` });
check("a grant for an account that does not exist -> 404", res.statusCode === 404);
for (const bad of [undefined, "", "no-dot", "a.b.c", 7]) {
  res = await redeem({ grant: bad });
  if (res.statusCode !== 404) check(`a malformed grant (${String(bad)}) -> 404`, false, String(res.statusCode));
}
check("malformed grants -> 404", true);
res = await handler(event({ method: "POST", path: "/badge-grant/redeem", body: "{" }));
check("a body that is not JSON -> 400", res.statusCode === 400);

// The limit is 3 collections (the default)
res = await redeem({ grant: good, consume: true });
check("a collection is counted, with its time", res.statusCode === 200 && bodyOf(res).valid === true && accounts.get(EMAIL).badgeCollections?.N === "1" && Boolean(accounts.get(EMAIL).badgeCollectedAt?.S));
res = await handler(await ask());
check("the account gets the same grant again while collections remain", res.statusCode === 200 && bodyOf(res).grant === good);
res = await redeem({ grant: good, consume: true });
const third = await redeem({ grant: good, consume: true });
check("a second and a third collection are allowed", res.statusCode === 200 && third.statusCode === 200 && accounts.get(EMAIL).badgeCollections?.N === "3");
res = await redeem({ grant: good, consume: true });
check("a fourth collection -> 409, and the count stays at 3", res.statusCode === 409 && bodyOf(res).collected === true && accounts.get(EMAIL).badgeCollections?.N === "3");
res = await redeem({ grant: good });
check("checking the grant at the limit -> 409", res.statusCode === 409 && bodyOf(res).valid === false);
res = await handler(await ask());
check("the account is refused a grant at the limit -> 409", res.statusCode === 409 && bodyOf(res).collected === true);

// A row from before collections were counted (a time and no count) reads as none collected
reset({ extra: { badgeCollectedAt: { S: "2026-11-20T00:00:00.000Z" } } });
res = await handler(await ask());
check("a row with a collection time and no count reads as none collected", res.statusCode === 200);

// Five uses at once with one collection left: exactly one succeeds
reset({ extra: { badgeCollections: { N: "2" } } });
const racing = bodyOf(await handler(await ask())).grant;
const raced = await Promise.all([1, 2, 3, 4, 5].map(() => redeem({ grant: racing, consume: true })));
check("five uses at once with one collection left: exactly one succeeds", raced.filter((r) => r.statusCode === 200).length === 1 && accounts.get(EMAIL).badgeCollections.N === "3");

// -- anything else
res = await handler(event({ method: "GET", path: "/badge-grant" }));
check("unknown route -> 404", res.statusCode === 404);

console.log(failures ? `\n${failures} FAILED` : "\nall checks passed");
process.exit(failures ? 1 : 0);
