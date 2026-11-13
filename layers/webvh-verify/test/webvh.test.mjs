// The resolver's cache: a document past its lifetime is validated against
// the log's ETag with a conditional fetch and kept when the log is
// unchanged, so the log is downloaded and walked again only when it
// changed. A real did:webvh log, minted here, stands in for the account.
//
//   cd layers/webvh-verify && npm install && npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { createDID, updateDID, signerFromDidKeySigner, logToJsonlString } from "@interop/did-method-webvh";
import { Ed25519VerificationKey } from "@interop/ed25519-verification-key";
import { resolveWebvhDocument, clearWebvhCache } from "../src/webvh.mjs";

const CACHE_MS = 30_000;

// A did:key with its private half, the way the wallet's bootstrap key is
// shaped: the signer needs the key's id set
async function keyPair() {
  const key = await Ed25519VerificationKey.generate();
  const multibase = key.fingerprint();
  key.controller = `did:key:${multibase}`;
  key.id = `${key.controller}#${multibase}`;
  return { key, multibase };
}

test("a log is fetched again only when it changed, validated by its ETag", async () => {
  clearWebvhCache();
  const { key, multibase } = await keyPair();
  const signer = signerFromDidKeySigner(key.signer());
  const { did, log, meta } = await createDID({
    address: "id.test",
    paths: ["space1"],
    signer,
    updateKeys: [`did:key:${multibase}`],
    verificationMethods: [{ type: "Multikey", publicKeyMultibase: multibase }],
    vmIdFragment: "multibase",
    portable: true,
    authentication: [`#${multibase}`],
    assertionMethod: [`#${multibase}`],
    capabilityInvocation: [`#${multibase}`],
    capabilityDelegation: [`#${multibase}`],
  });
  let text = logToJsonlString(log);
  let version = 1;
  const requests = [];
  globalThis.fetch = async (url, init) => {
    const ifNoneMatch = init?.headers?.["if-none-match"];
    requests.push({ url: String(url), ifNoneMatch });
    const etag = `"v${version}"`;
    if (ifNoneMatch === etag) {
      return new Response(null, { status: 304, headers: { etag } });
    }
    return new Response(text, { status: 200, headers: { etag, "content-type": "text/jsonl", "content-length": String(Buffer.byteLength(text)) } });
  };
  let clock = 1_000_000;
  const now = () => clock;
  const walks = () => requests.filter((r) => r.url.endsWith("/did.jsonl") && r.ifNoneMatch === undefined).length;
  const validations = () => requests.filter((r) => r.ifNoneMatch !== undefined).length;

  const first = await resolveWebvhDocument(did, { now });
  assert.equal(first.id, did);
  assert.ok(first.capabilityInvocation.includes(`${did}#${multibase}`), "the key is listed, with an absolute id");
  assert.equal(walks(), 1);
  // Within the lifetime: the cached document, no request
  clock += CACHE_MS / 2;
  assert.equal(await resolveWebvhDocument(did, { now }), first);
  assert.equal(requests.length, walks());
  // Past the lifetime, the log unchanged: a conditional fetch, a 304, the
  // same document, no walk
  clock += CACHE_MS;
  assert.equal(await resolveWebvhDocument(did, { now }), first);
  assert.equal(validations(), 1);
  assert.equal(walks(), 1);
  // A fresh resolution for a key the document does not list: the same
  assert.equal(await resolveWebvhDocument(did, { now, fresh: true }), first);
  assert.equal(validations(), 2);
  assert.equal(walks(), 1);
  // The log changed (a second key added): the next validation downloads and
  // walks it, and the new document lists the key
  const second = await keyPair();
  const updated = await updateDID({
    log,
    signer,
    updateKeys: [`did:key:${multibase}`],
    verificationMethods: [
      { type: "Multikey", publicKeyMultibase: multibase },
      { type: "Multikey", publicKeyMultibase: second.multibase },
    ],
    vmIdFragment: "multibase",
    capabilityInvocation: [`#${multibase}`, `#${second.multibase}`],
    priorMeta: meta,
  });
  text = logToJsonlString(updated.log);
  version = 2;
  const changed = await resolveWebvhDocument(did, { now, fresh: true });
  assert.ok(changed.capabilityInvocation.includes(`${did}#${second.multibase}`));
  assert.equal(validations(), 3);
  assert.equal(walks(), 1, "the changed log came back on the conditional fetch itself");
  // And the cache now serves the changed document
  clock += CACHE_MS / 2;
  assert.equal(await resolveWebvhDocument(did, { now }), changed);
});
