# lcw-back-end

> [!IMPORTANT]
> **Alpha.** This is part of the Learner Credential Wallet alpha, an early test
> version. It may change without notice. We read issues, but may not answer or
> fix them during the alpha.

Back-end infrastructure for the Learner Credential Wallet (LCW), defined with
[AWS SAM](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html)
and deployed as a single CloudFormation stack.

## What's here

A registration flow and a zCap-authenticated login endpoint:

- **`lcw-register`** — a Node.js Lambda invoked via `POST /register` with
  `{email, did, registrationCode, contactOptIn}`. It gates on the
  registration code, which must be a row of the PWS server's coupon table
  (`pws-coupons`) that has not expired and is not closed, and starts the
  registration state machine, passing on the code and the answer to the
  register page's "Contact me with news and updates" (anything but `true`
  is no). The code is not stored with the account.
  `cd src/lcw-register && npm install && npm test`.
- **`lcw-registration-codes`** — a Node.js Lambda invoked via
  `POST /registration-codes`, which mints a registration code for one
  person. The caller is the alpha application app's server, which presents
  the API key (see **`RegistrationCodeApiKeyParameter`** below) in the
  `x-api-key` header; the key must never be in a page a browser loads. The
  body is optional: `{"issuedTo": "..."}` is a note of who the code is for,
  kept on the row (the code is not tied to it: any email address can
  register with the code). The answer is `201` with
  `{code, link, expiresAt}`, where `link` opens the wallet's registration
  page with the code filled in (`<WalletUrl>/#/register?code=...`); the
  caller emails that link.

  ```bash
  curl -X POST https://api.lcw-sandbox.org/registration-codes \
    -H "x-api-key: $KEY" -H "Content-Type: application/json" \
    -d '{"issuedTo":"applicant@example.org"}'
  ```

  A minted code is for one account and is used up only when that account
  is complete. The row is written with `usesRemaining` set to
  `RegistrationCodeAttempts` (default 5) and `expiresAt` set
  `RegistrationCodeExpiryDays` ahead (default 90). The PWS server takes one
  use each time a wallet starts creating an account Space, so a signup that
  fails part-way leaves the code usable with the same link. When an account
  registered with the code is confirmed, the row is closed (`closedAt`, and
  `usesRemaining` zero) and neither the PWS server nor `POST /register`
  accepts it again. A person whose signups all fail before any is confirmed
  has no uses left after `RegistrationCodeAttempts` tries and needs a new
  code. `cd src/lcw-registration-codes && npm install && npm test`.
- **`lcw-create-account`** — a Node.js Lambda the state machine runs once
  the email is confirmed. It writes the account row and, for a minted code,
  closes the code in the same DynamoDB transaction, so two accounts
  confirmed with one code cannot both be recorded: the second gets an email
  saying the code has been used. A code with no `usesRemaining` (the
  deployment's shared code) is never closed.
  `cd src/lcw-create-account && npm install && npm test`.
- **`wallet-account-creator`** — a Step Functions state machine that registers
  an account: it emails the user a confirmation link (pausing on a task
  token), then records the account (email → `did` plus the contact choice)
  in the `lcw-accounts` DynamoDB table (through `lcw-create-account`) and
  emails the user a confirmation. The account's storage is not this stack's concern: the
  wallet creates its own account Space on the PWS server
  ([was-server-aws](../was-server-aws)), with the registration code as the
  coupon, as part of registering, and every further Space under that one
  with no code.
- **`registration-email-confirmation`** — a Node.js Lambda invoked via
  `GET /confirm?token=...` on an API Gateway HTTP API. When the user clicks
  the confirmation link, it calls `states:SendTaskSuccess` with the task token
  to resume the paused registration execution, passing the token's SHA-256
  as the account's `confirmationKey`, and shows a page that says the wallet
  is being set up. The page polls `GET /confirm/status?key=...` (the same
  function; a query on the table's `confirmationKey-index`) every two
  seconds and offers **Open my wallet** only once the account row is there,
  so the button cannot lead to a login before the account exists. After two
  minutes without the row it falls back to the "you will receive an email"
  text; without scripting it shows the button straight away, as before.
  `cd src/registration-email-confirmation && npm install && npm test` runs
  its tests with Step Functions and DynamoDB mocked.
- **`lcw-login`** — a Node.js Lambda invoked via `POST /login` with a JSON
  body containing an `email`. It verifies the request's
  [HTTP-signature capability invocation](https://github.com/interop-alliance/http-signature-zcap-verify)
  headers against a root capability controlled by the DID registered for that
  email, or by the client-annex DID that account's document names under the
  `https://w3id.org/byoe#DelegatedClients` service type (a wallet session
  opened with a password is a transient client of that annex, whose keys the
  annex document lists; one opened with a passkey is an enrolled client the
  account document lists itself; a signer the cached document does not
  name is checked once more against a fresh resolution, since a recovery
  login re-points the annex entry and signs in at once), and on success
  answers `{verified, email, controller}`. Identity
  only: the wallet lists its spaces through the PWS server. All rejections
  return a generic 401.
- **`lcw-recovery`** — a Node.js Lambda holding each account's recovery code.
  The wallet mints a code, binds it as a credential of the account, and
  stores it with `PUT /recovery` (signed as the account, verified the way
  `/login` is); `GET /recovery?email=` says whether one is stored. **`POST
  /forgot`** `{email}` emails the code to the address the account registered
  and answers the same whether or not the account or a code exists; it is
  limited to three emails per address per hour. Codes are encrypted under
  the stack's `RecoveryKey` (KMS, the email as encryption context) in the
  `lcw-recovery` table. This is the one place the server holds a secret that
  unlocks an account's data: whoever can read the table, decrypt with the
  key, and receive the registered address's mail can open the account. The
  controls are the encryption at rest, the registered address as the only
  destination, the rate limit, the log line per send, and the wallet
  replacing the code after every use.
- **`lcw-badge`** — a Node.js Lambda for the account's grant for the LCW
  Alpha Testing Badge, which lets the badge's issuer (aws-lambda-issuer)
  issue it to wallet accounts only, once each. `POST /badge-grant`
  `{email}`, signed as the account, answers `{grant}` (the same one until
  the badge is collected, then `409`). `POST /badge-grant/redeem`
  `{grant, consume?}` is the issuer's: not signed, since the grant is the
  secret; it answers `{valid: true}`, and with `consume` counts one
  collection. An account may collect the badge `BadgeCollectionLimit` times
  (a stack parameter, default 3, so a holder who deletes it by accident can
  collect it again); after that both routes answer `409`. The grant's
  secret, the count and the time of the last collection are kept on the
  account row (`badgeGrant`, `badgeCollections`, `badgeCollectedAt`).
  `POST /login` answers `badgeAvailable`, so the wallet knows whether to
  offer the badge. `cd src/lcw-badge && npm install && npm test`.
- **`lcw-contact`** — a Node.js Lambda holding the tester's answer to
  "Contact me with news and updates", asked at registration and changed
  from the wallet's Settings: `GET /contact?email=` answers
  `{contactOptIn, updatedAt}` and `PUT /contact` `{email, contactOptIn}`
  records a change, both signed as the account and verified the way `/login`
  is. Its role can update only the two contact attributes of a row, never
  its `did`. The team's list of who agreed is the admin
  console's ([lcw-admin-back-end](https://github.com/digitalcredentials/lcw-admin-back-end)),
  which reads the same table. `cd src/lcw-contact && npm install && npm
  test` runs its tests with real signed invocations.
- **`webvh-verify`** (`layers/webvh-verify/`) — a Lambda layer holding the
  one copy of the zCap invocation verifier `lcw-login`, `lcw-recovery` and
  `lcw-contact` share with the batch issuer's notify function
  ([batch-issuer-backend](../batch-issuer-backend)): the invocation of the
  request's own URL must be signed by the DID registered for the email, and
  a registered `did:webvh` is controlled by whichever keys its log's current
  document lists (fetched from the identity domain, cached for
  `WEBVH_CACHE_SECONDS` and then validated with a conditional fetch against
  the log's ETag, so an unchanged log keeps the document and the walk it
  cost, and a log that grows with every client and credential is fetched
  and walked again only when it changed; a key the cached document does not
  list takes the same conditional fetch). `cd layers/webvh-verify && npm
  test` runs the resolver's test over a log minted on the spot. The layer is bundled with its
  dependencies into one ES module (`npm run build`), the functions leave
  `webvh-verify` external and import it from the layer at runtime, and the
  stack publishes the current layer version's ARN in the SSM parameter
  `/lcw/webvh-verify-layer-arn` for the batch issuer's stack to read. Old
  versions are retained, since that stack references one until its next
  deploy.
- **`lcw-accounts`** — the DynamoDB accounts table (partition key `email`,
  on-demand billing) holding each account's `did`,
  `CreatedAt`, and contact choice (`contactOptIn`, `contactOptInUpdatedAt`;
  a row without them, an account registered before the question, reads as
  no). A row written before 2026-11-19 also holds the registration code the
  account was made with, as `token`; nothing reads it.

| Path | Purpose |
| --- | --- |
| `template.yaml` | SAM template: the HTTP API, the Lambdas, the state machine, the DynamoDB tables, IAM policies, and log groups |
| `src/lcw-register/index.mjs` | Registration Lambda handler |
| `src/registration-email-confirmation/index.mjs` | Confirmation Lambda handler |
| `layers/webvh-verify/` | The shared invocation verifier, as a Lambda layer (`src/`, bundled to `dist/` by `npm run build`; `Makefile` for `sam build`) |
| `src/lcw-login/index.mjs` | Login Lambda handler |
| `src/lcw-login/test/local-test.mjs` | Local test for the login handler |
| `src/lcw-login/test/wire-test.mjs` | Signed end-to-end test against the local API |
| `src/lcw-badge/index.mjs` | Badge-grant Lambda handler |
| `src/lcw-badge/test/local-test.mjs` | Local test for the badge-grant handler |
| `src/lcw-contact/index.mjs` | Contact-choice Lambda handler |
| `src/lcw-contact/test/local-test.mjs` | Local test for the contact-choice handler |

## Parameters

- **`DomainName`** / **`HostedZoneId`** — the registered domain
  (lcw-sandbox.org) and its Route 53 zone; the template writes the SES DKIM
  and inbound MX records there.
- **`FromEmail`** — the address registration emails are sent from and inbound
  mail is received on (default `registration@lcw-sandbox.org`). Inbound mail
  is stored in S3 by an SES receipt rule and forwarded by the
  `lcw-mail-forwarder` Lambda to **`ForwardTo`** (default
  `james.chartrand@dccommons.org`). CloudFormation cannot activate a receipt
  rule set, so after the first deploy run
  `aws ses set-active-receipt-rule-set --rule-set-name lcw-sandbox-inbound`.
- **`CouponsTableName`** — the PWS server's coupon table (default
  `pws-coupons`), in the same account and region. Registration codes are
  its rows; there is no registration code parameter. A deployment's shared
  code, if it has one, is a row with no `usesRemaining`, added by hand as
  the PWS server's README shows; removing that row ends registration with
  it.
- **`RegistrationCodeAttempts`** (default 5) and
  **`RegistrationCodeExpiryDays`** (default 90) — see
  `lcw-registration-codes` above.
- **`RegistrationCodeApiKeyParameter`** — the name of the Parameter Store
  SecureString holding the API key for `POST /registration-codes` (default
  `/lcw/registration-codes/api-key`). CloudFormation cannot create a
  SecureString, so make it by hand before the first call:

  ```bash
  aws ssm put-parameter --name /lcw/registration-codes/api-key \
    --type SecureString --value "$(openssl rand -base64 32)"
  ```

  To replace the key, run the same command with `--overwrite`; the function
  reads the parameter again within five minutes.
## Prerequisites

- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
- AWS credentials configured for the target account (e.g. via `aws configure` or SSO)

The `lcw-login` function is bundled with esbuild at build time (pinned as a
devDependency), which resolves a CJS→ESM `require` in its dependency graph
that the Lambda runtime would otherwise refuse at init.

## Deploy

```bash
sam build
sam deploy --guided
```

The `--guided` flag walks you through stack name, region, and deployment
settings on the first deploy, and offers to save them to `samconfig.toml`
so subsequent deploys are just:

```bash
sam build && sam deploy
```

The stack outputs:

- **`ConfirmUrl`** — the base URL for confirmation links (append `?token=...`);
  the state machine embeds it in confirmation emails automatically.
- **`LoginUrl`** — the zCap-authenticated login endpoint (POST).
- **`FunctionArn`** — the confirmation Lambda's ARN.
- **`StateMachineArn`** — the registration state machine's ARN.

## Local testing

### Login flow

```bash
cd src/lcw-login
npm install
npm test
```

The test runs the handler in-process against a mocked DynamoDB table and
prints the response for each scenario — malformed bodies, unsigned requests,
signatures from the wrong DID, and a fully signed capability invocation
(generated with a fresh `did:key`) that succeeds end to end. The handler
imports the verifier from `webvh-verify`, which the function's
`devDependencies` link to `layers/webvh-verify`; `npm test` first builds
that layer's bundle (`pretest`), since the verifier only loads bundled.
`src/lcw-recovery` tests the same way.

### Running the API locally

The front end and the wire test expect the API on port 3001 (the local
was-server-aws API uses 3000). Outside CloudFormation `sam local` resolves the
`TABLE_NAME: !Ref AccountsTable` env var to the literal logical ID, so it
needs an override file:

```bash
cat > env.json <<'JSON'
{ "LcwLoginFunction": { "TABLE_NAME": "lcw-accounts" } }
JSON
sam build
sam local start-api --port 3001 --region us-east-1 --env-vars env.json --warm-containers EAGER
```

Docker must be running; the Lambda reads the **real** `lcw-accounts` table with
your local AWS credentials.

### Signed login over the wire

```bash
cd src/lcw-login
node test/wire-test.mjs
```

Registers a temporary account in the real `lcw-accounts` table (key derived
from SHA-256 of a password, the same derivation the front end uses), POSTs a
signed capability invocation over HTTP to the local API on port 3001, checks
both the success and wrong-password paths, and cleans up.

### Confirmation route

```bash
sam build
sam local start-api
curl "http://localhost:3000/confirm?token=test-token"
```

(The `SendTaskSuccess` call will fail without a real task token from a
running Step Functions execution, but this exercises the routing and
error handling.) `curl "http://localhost:3000/confirm/status?key=<64 hex>"`
exercises the status route, which answers `{"ready":false}` for a key no
account carries.

## Validate the template

```bash
sam validate --lint
```

## License

MIT. See [LICENSE](LICENSE).
