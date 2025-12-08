const apiUrlGet  = "https://api.jsonstorage.net/v1/json/087395de-f632-4250-a29b-ad3addce7310/f5e3a1da-067d-4f27-b54d-7fdcef80c741";

export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        if (url.pathname === "/health") {
            return Response.json({ status: "ok" });
        }

        if (url.pathname === "/webhook/cakto" && request.method === "POST") {
            return handleWebhook(request, env);
        }

        if (url.pathname === "/verify" && request.method === "POST") {
            return handleVerify(request, env);
        }

        return new Response("Not found", { status: 404 });
    }
};

// ============================================================================
// STORAGE
// ============================================================================

async function getRemoteData() {
    try {
        const response = await fetch(apiUrlGet);
        if (!response.ok) return [];
        return await response.json();
    } catch (_) {
        return [];
    }
}

async function updateRemoteData(data, env) {
    try {
        const url = apiUrlGet + "?apiKey=" + env.JSONKEY;
        const res = await fetch(url, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data)
        });
        return res.ok;
    } catch (_) {
        return false;
    }
}

async function addEmail(email, env) {
    if (!email) return false;

    const data = await getRemoteData();
    const emails = Array.isArray(data) ? data : [];

    if (!emails.includes(email)) {
        emails.push(email);
        return await updateRemoteData(emails, env);
    }

    return true;
}

async function removeEmail(email, env) {
    if (!email) return false;

    const data = await getRemoteData();
    const emails = Array.isArray(data) ? data : [];
    const filtered = emails.filter(e => e !== email);

    if (filtered.length !== emails.length) {
        return await updateRemoteData(filtered, env);
    }

    return true;
}

// ============================================================================
// WEBHOOK
// ============================================================================

async function handleWebhook(request, env) {
    try {
        const body = await request.json();
        const event = body?.event;
        const email = body?.data?.customer?.email;

        switch (event) {
            case "purchase_approved":
            case "subscription_created":
            case "subscription_renewed":
                await addEmail(email, env);
                break;

            case "subscription_canceled":
            case "subscription_renewal_refused":
            case "refund":
            case "chargeback":
                await removeEmail(email, env);
                break;

            case "purchase_refused":
                break;

            default:
                break;
        }

        return Response.json({ success: true });
    } catch (error) {
        return Response.json({ error: error.message }, { status: 500 });
    }
}

// ============================================================================
// VERIFY
// ============================================================================

async function handleVerify(request, env) {
    try {
        const body = await request.json();
        const email = body.email;
        const token = body.token;

        if (!email || !token) {
            return Response.json({ error: "Email and token required" }, { status: 400 });
        }

        const expectedToken = await sha256(email + env.SECRET_KEY);

        if (token !== expectedToken) {
            return Response.json({ error: "Invalid token" }, { status: 401 });
        }

        const emails = await getRemoteData();
        const isBuyer = Array.isArray(emails) && emails.includes(email);

        return Response.json({ buyer: isBuyer });
    } catch (_) {
        return Response.json({ error: "Internal error" }, { status: 500 });
    }
}

// ============================================================================
// HELPERS
// ============================================================================

async function sha256(text) {
    const data = new TextEncoder().encode(text);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}