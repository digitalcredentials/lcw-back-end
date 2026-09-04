import { SFNClient, SendTaskSuccessCommand } from "@aws-sdk/client-sfn";

const sfnClient = new SFNClient();

export const handler = async (event) => {
    // 1. Extract the token from the URL query parameters
    const rawQueryString = event.rawQueryString; 
    if (!rawQueryString || rawQueryString.length < 7) { // "token=" is 6 characters, so we need at least 7
        return {
            statusCode: 400,
            headers: { "Content-Type": "text/html" },
            body: "<h1>Error</h1><p>Missing confirmation token, or any params for that matter.</p>"
        };
    }
    
    const token = rawQueryString.slice(6); // Remove "token=" prefix to get the actual token value

    if (!token) {
        return {
            statusCode: 400,
            headers: { "Content-Type": "text/html" },
            body: "<h1>Error</h1><p>Missing confirmation token from query params.</p>"
        };
    }

    try {
        // 2. Send the token back to Step Functions to resume execution
        const command = new SendTaskSuccessCommand({
            taskToken: token,
            output: JSON.stringify({ confirmationStatus: "VERIFIED" }) 
        });
        await sfnClient.send(command);

        // 3. Return a clean HTML success page to the user
        return {
            statusCode: 200,
            headers: { "Content-Type": "text/html" },
            body: "<h1>Email Confirmed!</h1><p>Your verification was successful. You can now close this tab.</p>"
        };
    } catch (error) {
        console.error("Error resuming step function:", error);
        return {
            statusCode: 500,
            headers: { "Content-Type": "text/html" },
            body: `<h1>Error</h1><p>Failed to verify email. The link may have expired or have been already confirmed.</p>
            <p>Error details: ${error.message}</p><p>The token: ${token}</p>
            <p>The query string: ${rawQueryString}</p>`
        };
    }
};
