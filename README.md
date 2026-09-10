# lcw-back-end

Back-end infrastructure for the Learner Credential Wallet (LCW), defined with
[AWS SAM](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html)
and deployed as a single CloudFormation stack.

## What's here

A registration flow and a zCap-authenticated login endpoint:

- **`wallet-account-creator`** — a Step Functions state machine that registers
  an account: it emails the user a confirmation link (pausing on a task
  token), then creates an S3 bucket for the account's
  [Wallet Attached Storage](https://w3c-ccg.github.io/wallet-attached-storage-spec/)
  space, records the account (email, DID, space URL) in the `wallet-test`
  DynamoDB table, uploads an initial file, and emails the user their space
  URL.
- **`registration-email-confirmation`** — a Node.js Lambda invoked via
  `GET /confirm?token=...` on an API Gateway HTTP API. When the user clicks
  the confirmation link, it calls `states:SendTaskSuccess` with the task token
  to resume the paused registration execution.
- **`lcw-login`** — a Node.js Lambda invoked via `POST /login` with a JSON
  body containing an `email`. It verifies the request's
  [HTTP-signature capability invocation](https://github.com/interop-alliance/http-signature-zcap-verify)
  headers against a root capability controlled by the DID registered for that
  email, and on success returns the account's space URL. All rejections
  return a generic 401.
- **`wallet-test`** — the DynamoDB accounts table (partition key `email`,
  on-demand billing) holding each account's `did`, `spaceURL`, and
  `CreatedAt`.

| Path | Purpose |
| --- | --- |
| `template.yaml` | SAM template: the HTTP API, both Lambdas, the state machine, the DynamoDB table, IAM policies, and log groups |
| `src/registration-email-confirmation/index.mjs` | Confirmation Lambda handler |
| `src/lcw-login/index.mjs` | Login Lambda handler |
| `src/lcw-login/test/local-test.mjs` | Local test for the login handler |
| `src/lcw-login/test/wire-test.mjs` | Signed end-to-end test against the local API |

## Parameters

- **`SpaceBaseUrl`** — base URL for Wallet Attached Storage space URLs
  (typically ending in `/space`). At registration the state machine appends
  the account's space id after a slash and stores the result as the account's
  `spaceURL`. The default is a placeholder; set the real WAS server URL at
  deploy time:

  ```bash
  sam deploy --parameter-overrides SpaceBaseUrl=https://your-was-server/space
  ```

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
(generated with a fresh `did:key`) that succeeds end to end.

### Running the API locally

The front end and the wire test expect the API on port 3001 (the local
was-server-aws API uses 3000). Outside CloudFormation `sam local` resolves the
`TABLE_NAME: !Ref WalletTestTable` env var to the literal logical ID, so it
needs an override file:

```bash
cat > env.json <<'JSON'
{ "LcwLoginFunction": { "TABLE_NAME": "wallet-test" } }
JSON
sam build
sam local start-api --port 3001 --region us-east-1 --env-vars env.json --warm-containers EAGER
```

Docker must be running; the Lambda reads the **real** `wallet-test` table with
your local AWS credentials.

### Signed login over the wire

```bash
cd src/lcw-login
node test/wire-test.mjs
```

Registers a temporary account in the real `wallet-test` table (key derived
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
error handling.)

## Validate the template

```bash
sam validate --lint
```
