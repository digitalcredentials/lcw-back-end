import { SFNClient, StartExecutionCommand } from "@aws-sdk/client-sfn";

const sfnClient = new SFNClient();

const json = (statusCode, body) => ({
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
});

export const handler = async (event) => {
    // 1. Extract the registration fields from the JSON POST body
    let email, did, registrationCode;
    try {
        const rawBody = event.isBase64Encoded
            ? Buffer.from(event.body ?? "", "base64").toString("utf8")
            : event.body;
        ({ email, did, registrationCode } = JSON.parse(rawBody ?? "{}"));
    } catch {
        return json(400, { error: "Request body must be valid JSON." });
    }

    if (!email || !did) {
        return json(400, { error: "Missing email or did in request body." });
    }

    // 2. Gate registration on the code configured for the deployment
    const expected = process.env.REGISTRATION_CODE;
    if (!expected) {
        console.error("REGISTRATION_CODE is not configured");
        return json(500, { error: "Registration is not available." });
    }
    if (registrationCode !== expected) {
        return json(403, {
            error: "Your registration code isn't valid. Please try again or obtain a new code."
        });
    }

    // 3. Start the registration state machine; it emails the confirmation
    // link and, once confirmed, provisions the account
    try {
        await sfnClient.send(new StartExecutionCommand({
            stateMachineArn: process.env.STATE_MACHINE_ARN,
            input: JSON.stringify({ recipientEmail: email, did })
        }));
    } catch (error) {
        console.error("Error starting registration execution:", error);
        return json(500, { error: "Registration failed. Please try again later." });
    }

    return json(202, {
        message: "Registration started. Check your email for a confirmation link."
    });
};
