# lcw-back-end

Back-end infrastructure for the Learner Credential Wallet (LCW), defined with
[AWS SAM](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html).

## What's here

An email confirmation callback for the registration flow:

- **`registration-email-confirmation`** — a Node.js Lambda function invoked via
  `GET /confirm?token=...` on an API Gateway HTTP API. The registration flow
  (a Step Functions execution) pauses and emails the user a confirmation link
  containing a task token; when the user clicks the link, this function calls
  `states:SendTaskSuccess` with that token to resume the execution, then returns
  a simple HTML confirmation page.

| Path | Purpose |
| --- | --- |
| `template.yaml` | SAM template: the Lambda function, HTTP API route, IAM policy, and log group |
| `src/index.mjs` | Lambda handler |

## Prerequisites

- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
- AWS credentials configured for the target account (e.g. via `aws configure` or SSO)

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

The stack outputs `ConfirmUrl` — the base URL for confirmation links
(append `?token=...`). This is the URL the registration flow should embed
in confirmation emails.

## Local testing

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
