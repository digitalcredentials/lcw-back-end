import { SFNClient, SendTaskSuccessCommand } from "@aws-sdk/client-sfn";

// GET /confirm?token=... -- the link in the "confirm your email address"
// message. It hands the task token back to the registration state machine,
// which then creates the account, and shows the person a page.

const sfnClient = new SFNClient();

const WALLET_URL = process.env.WALLET_URL ?? "https://lcw-sandbox.org";
const ORG_NAME = process.env.ORG_NAME ?? "Digital Credentials Commons";
const LOGO_URL = process.env.LOGO_URL ?? "https://digitalcredentials.github.io/badge-assets/dcc-commons-mark.png";

const escapeHtml = (text) => String(text).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

// The same layout as the emails: logo and organisation name at the top, a
// footer at the bottom.
function page({ title, paragraphs, button }) {
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
      ${paragraphs.map((text) => `<p>${escapeHtml(text)}</p>`).join("\n      ")}
      ${button ? `<p style="margin:24px 0;"><a href="${escapeHtml(button.url)}" style="display:inline-block;background:#4f46e5;color:#ffffff;text-decoration:none;padding:12px 20px;border-radius:8px;font-weight:600;">${escapeHtml(button.label)}</a></p>` : ""}
    </div>
    <div style="padding:16px 32px;border-top:1px solid #e5e7eb;font-size:13px;color:#6b7280;">${escapeHtml(ORG_NAME)} &middot; Learner Credential Wallet</div>
  </div>
</div>
</body>
</html>
`;
}

const html = (statusCode, body) => ({
  statusCode,
  headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
  body,
});

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

export const handler = async (event) => {
  const token = tokenFrom(event.rawQueryString);
  if (!token) {
    return html(400, page({
      title: "This link is incomplete",
      paragraphs: ["The confirmation link is missing its token. Please open the link from the email again."],
    }));
  }

  try {
    await sfnClient.send(new SendTaskSuccessCommand({
      taskToken: token,
      output: JSON.stringify({ confirmationStatus: "VERIFIED" }),
    }));
  } catch (error) {
    console.error("Error resuming the registration:", error);
    return html(400, page({
      title: "This link no longer works",
      paragraphs: [
        "The confirmation link may have expired, or the email address may already have been confirmed.",
        "If you have already confirmed, you can sign in to your wallet.",
      ],
      button: { label: "Open my wallet", url: WALLET_URL },
    }));
  }

  return html(200, page({
    title: "Email confirmed",
    paragraphs: [
      "Thank you. Your wallet account is being set up; you will receive one more email when it is ready.",
      "You can close this tab, or open the wallet now.",
    ],
    button: { label: "Open my wallet", url: WALLET_URL },
  }));
};
