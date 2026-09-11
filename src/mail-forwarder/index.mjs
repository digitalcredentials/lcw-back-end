import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { SESv2Client, SendEmailCommand } from "@aws-sdk/client-sesv2";

const s3 = new S3Client({});
const ses = new SESv2Client({});

const BUCKET = process.env.MAIL_BUCKET;
const FORWARD_FROM = process.env.FORWARD_FROM; // a verified SES identity
const FORWARD_TO = process.env.FORWARD_TO;

// Forwards mail received by SES (stored in S3 by the receipt rule) to
// FORWARD_TO. SES only sends from verified identities, so the From header is
// rewritten to FORWARD_FROM and the original sender preserved in Reply-To.
export const handler = async (event) => {
    const { mail } = event.Records[0].ses;

    const { Body } = await s3.send(new GetObjectCommand({
        Bucket: BUCKET,
        Key: `inbound/${mail.messageId}`
    }));
    const raw = await Body.transformToString();

    // Split headers from body; rewrite only what SES requires
    const separator = raw.indexOf("\r\n\r\n") !== -1 ? "\r\n\r\n" : "\n\n";
    const splitAt = raw.indexOf(separator);
    const headerText = raw.slice(0, splitAt);
    const body = raw.slice(splitAt);

    // Unfold headers so multi-line values filter as one unit
    const headers = headerText.replace(/\r?\n[ \t]+/g, " ").split(/\r?\n/);

    const originalFrom = headers.find((h) => /^from:/i.test(h))?.slice(5).trim() ?? "";
    const kept = headers.filter(
        (h) => !/^(from|sender|return-path|reply-to|dkim-signature|received-spf|authentication-results):/i.test(h)
    );

    // The original sender's display name survives in the rewritten From
    const displayName = originalFrom.replace(/<[^>]*>/, "").replace(/"/g, "").trim();
    const newHeaders = [
        `From: ${displayName ? `"${displayName} (via ${FORWARD_FROM})" ` : ""}<${FORWARD_FROM}>`,
        ...(originalFrom ? [`Reply-To: ${originalFrom}`] : []),
        ...kept
    ];

    await ses.send(new SendEmailCommand({
        FromEmailAddress: FORWARD_FROM,
        Destination: { ToAddresses: [FORWARD_TO] },
        Content: { Raw: { Data: Buffer.from(newHeaders.join("\r\n") + body) } }
    }));

    console.log(`forwarded ${mail.messageId} (from ${originalFrom || "unknown"}) to ${FORWARD_TO}`);
};
