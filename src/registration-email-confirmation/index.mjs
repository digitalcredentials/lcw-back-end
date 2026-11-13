import { createHash } from "node:crypto";
import { SFNClient, SendTaskSuccessCommand } from "@aws-sdk/client-sfn";
import { DynamoDBClient, QueryCommand } from "@aws-sdk/client-dynamodb";

// GET /confirm?token=... -- the link in the "confirm your email address"
// message. It hands the task token back to the registration state machine,
// which then creates the account, and shows the person a page that waits
// for the account before offering to open the wallet: the page polls
// GET /confirm/status?key=... (the hash of the token, which the state
// machine stores on the account row) until the row is there.

const sfnClient = new SFNClient();
const dynamoClient = new DynamoDBClient();
const WALLET_URL = process.env.WALLET_URL ?? "https://lcw-sandbox.org";
const ORG_NAME = process.env.ORG_NAME ?? "Digital Credentials Commons";
const LOGO_URL = process.env.LOGO_URL ?? "https://digitalcredentials.github.io/badge-assets/dcc-commons-mark.png";
const TABLE_NAME = process.env.TABLE_NAME ?? "lcw-accounts";
const CONFIRMATION_INDEX = "confirmationKey-index";
// How long the page keeps asking before it falls back to the email
const POLL_FOR_MS = 120_000;
const POLL_EVERY_MS = 2_000;

const escapeHtml = (text) => String(text).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

// The confirmation key: the hash of the task token, so the page can ask
// after the account without holding the email or the token itself
export const confirmationKeyOf = (token) => createHash("sha256").update(token).digest("hex");

const BUTTON_STYLE = "display:inline-block;background:#4f46e5;color:#ffffff;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:600;";

// The same layout as the emails: logo and organisation name at the top, a
// footer at the bottom. `body` is HTML the caller already escaped.
function page({ title, body }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<link rel="icon" href="${escapeHtml(LOGO_URL)}">
</head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1f2937;">
<div style="max-width:560px;margin:40px auto;padding:0 16px;">
  <div style="background:#ffffff;border-radius:12px;border:1px solid #e5e7eb;">
    <div style="padding:24px 32px 8px 32px;">
      <img src="${escapeHtml(LOGO_URL)}" alt="" width="44" height="44" style="vertical-align:middle;border:0;">
      <span style="font-size:16px;font-weight:600;vertical-align:middle;margin-left:10px;">${escapeHtml(ORG_NAME)}</span>
    </div>
    <div style="padding:8px 32px 32px 32px;font-size:16px;line-height:1.5;">
      <h1 style="font-size:22px;margin:16px 0;">${escapeHtml(title)}</h1>
      ${body}
    </div>
    <div style="padding:16px 32px;border-top:1px solid #e5e7eb;font-size:13px;color:#6b7280;">${escapeHtml(ORG_NAME)} &middot; Learner Credential Wallet</div>
  </div>
</div>
</body>
</html>
`;
}

const paragraphs = (texts) => texts.map((text) => `<p>${escapeHtml(text)}</p>`).join("\n      ");
const button = ({ label, url }) =>
  `<p style="margin:24px 0;"><a href="${escapeHtml(url)}" style="${BUTTON_STYLE}">${escapeHtml(label)}</a></p>`;

const html = (statusCode, body) => ({
  statusCode,
  headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  body,
});
const json = (statusCode, body) => ({
  statusCode,
  headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  body: JSON.stringify(body),
});

// The page shown once the token is accepted: it says the account is being
// set up and asks the status route every two seconds; the button appears
// when the account row is there. Without scripting, the email remains the
// signal, as before.
function waitingPage(key) {
  const waiting = paragraphs(["Thank you. Hang tight, we are setting up your wallet."]);
  const ready = paragraphs(["Your wallet is ready. Sign in with your email address and the passphrase you chose."]) + button({ label: "Open my wallet", url: WALLET_URL });
  const late = paragraphs([
    "This is taking longer than expected. You will receive an email when your wallet is ready; sign in then with your email address and the passphrase you chose.",
  ]);
  const fallback = paragraphs([
    "Thank you. Your wallet account is being set up; you will receive one more email when it is ready.",
    "You can close this tab, or open the wallet now.",
  ]) + button({ label: "Open my wallet", url: WALLET_URL });
  return page({
    title: "Email confirmed",
    body: `<div id="status">${waiting}</div>
      <noscript>${fallback}</noscript>
      <script>
      (function () {
        var status = document.getElementById("status");
        var ready = ${JSON.stringify(ready)};
        var late = ${JSON.stringify(late)};
        var url = "/confirm/status?key=${escapeHtml(key)}";
        var until = Date.now() + ${POLL_FOR_MS};
        function again() {
          if (Date.now() > until) { status.innerHTML = late; return; }
          setTimeout(ask, ${POLL_EVERY_MS});
        }
        function ask() {
          fetch(url, { cache: "no-store" })
            .then(function (res) { return res.json(); })
            .then(function (body) { if (body && body.ready) { status.innerHTML = ready; } else { again(); } })
            .catch(again);
        }
        ask();
      })();
      </script>`,
  });
}

// The task token is the raw value after `token=`. Base64 task tokens carry
// `+`, `/` and `=`, so the query is not parsed with URLSearchParams (which
// reads `+` as a space); a percent-encoded token (what the email now sends)
// decodes, and an unencoded one passes through unchanged.
function tokenFrom(rawQueryString = "") {
  const raw = rawQueryString.startsWith("token=") ? rawQueryString.slice("token=".length) : "";
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

// GET /confirm/status?key=<sha-256 hex>: whether the account the key names
// has been created. A malformed key is refused; an unknown one is "not yet".
async function status(event) {
  const key = event.queryStringParameters?.key ?? "";
  if (!/^[0-9a-f]{64}$/.test(key)) {
    return json(400, { error: "Missing or malformed key." });
  }
  try {
    const { Count } = await dynamoClient.send(new QueryCommand({
      TableName: TABLE_NAME,
      IndexName: CONFIRMATION_INDEX,
      KeyConditionExpression: "confirmationKey = :key",
      ExpressionAttributeValues: { ":key": { S: key } },
      Select: "COUNT",
      Limit: 1,
    }));
    return json(200, { ready: (Count ?? 0) > 0 });
  } catch (error) {
    console.error("Error looking up the account by confirmation key:", error);
    return json(500, { error: "Failed to look up the account." });
  }
}

async function confirm(event) {
  const token = tokenFrom(event.rawQueryString);
  if (!token) {
    return html(400, page({
      title: "This link is incomplete",
      body: paragraphs(["The confirmation link is missing its token. Please open the link from the email again."]),
    }));
  }
  const key = confirmationKeyOf(token);
  try {
    await sfnClient.send(new SendTaskSuccessCommand({
      taskToken: token,
      output: JSON.stringify({ confirmationStatus: "VERIFIED", confirmationKey: key }),
    }));
  } catch (error) {
    console.error("Error resuming the registration:", error);
    return html(400, page({
      title: "This link no longer works",
      body: paragraphs([
        "The confirmation link may have expired, or the email address may already have been confirmed.",
        "If you have already confirmed, you can sign in to your wallet.",
      ]) + button({ label: "Open my wallet", url: WALLET_URL }),
    }));
  }
  return html(200, waitingPage(key));
}

export const handler = async (event) => {
  const path = event.rawPath ?? "";
  if (path.endsWith("/confirm/status")) {
    return status(event);
  }
  return confirm(event);
};
