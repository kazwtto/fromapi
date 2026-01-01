let apiUrlGet, apiUrlAdm;
const rateLimitMap = new Map();

export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        if (!apiUrlAdm) {
            apiUrlGet = env.USERS_ENDPOINT;
            apiUrlAdm = env.ADMIN_ENDPOINT;
        }

        const corsHeaders = {
            'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
            'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        };

        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        if (url.pathname === "/health" || url.pathname === "/health.html") {
            return Response.json({ status: "ok" }, { headers: corsHeaders });
        }

        if ((url.pathname === "/webhook/cakto" || url.pathname === "/webhook/cakto.html") && request.method === "POST") {
            return handleWebhook(request, env, corsHeaders);
        }

        if ((url.pathname === "/cakto/login" || url.pathname === "/cakto/login.html") && request.method === "POST") {
            return handleCaktoLogin(request, env, corsHeaders);
        }
        
        if ((url.pathname === "/admin/login" || url.pathname === "/admin/login.html") && request.method === "POST") {
            return handleAdminLogin(request, env, corsHeaders);
        }
        
        if ((url.pathname === "/admin/users" || url.pathname === "/admin/users.html") && request.method === "GET") {
            const auth = await requireAdmin(request, env);
            
            if (!auth.authorized) {
                return Response.json(
                    { error: "Não autorizado" }, 
                    { status: 401, headers: corsHeaders }
                );
            }
            
            const emails = await getRemoteData();
            return Response.json({ users: emails }, { headers: corsHeaders });
        }

        if ((url.pathname === "/verify-token" || url.pathname === "/verify-token.html") && request.method === "POST") {
            return handleVerifyToken(request, env, corsHeaders);
        }

        return new Response("Not found", { status: 404, headers: corsHeaders });
    }
};

// ============================================================================
// STORAGE
// ============================================================================

async function requireAdmin(request, env) {
    const authHeader = request.headers.get('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return { authorized: false };
    }
    
    const token = authHeader.replace('Bearer ', '');
    const payload = await verifySessionToken(token, env);
    
    if (!payload || payload.type !== 'admin') {
        return { authorized: false };
    }
    
    return { authorized: true, user: payload.user };
}

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

function getAdminUsers(env) {
    try {
        return typeof env.ADMIN_USERS === 'string' ? JSON.parse(env.ADMIN_USERS) : env.ADMIN_USERS;
    } catch (_) {
        return [];
    }
}

// ============================================================================
// WEBHOOK
// ============================================================================

async function handleWebhook(request, env, corsHeaders) {
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
            default:
                break;
        }

        return Response.json({ success: true }, { headers: corsHeaders });
    } catch (error) {
        return Response.json({ error: error.message }, { 
            status: 500, 
            headers: corsHeaders 
        });
    }
}

// ============================================================================
// LOGIN CAKTO
// ============================================================================

async function handleCaktoLogin(request, env, corsHeaders) {
    try {
        const body = await request.json();
        const email = body.email?.toLowerCase()?.trim();

        if (!email || !isValidEmail(email)) {
            return Response.json(
                { error: "Email inválido" }, 
                { status: 400, headers: corsHeaders }
            );
        }

        const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
        if (!checkRateLimit(clientIP)) {
            return Response.json(
                { error: "Muitas tentativas. Aguarde um momento." },
                { status: 429, headers: corsHeaders }
            );
        }

        const emails = await getRemoteData();
        const isBuyer = Array.isArray(emails) && emails.includes(email);

        if (!isBuyer) {
            return Response.json(
                { error: "Email não autorizado" },
                { status: 403, headers: corsHeaders }
            );
        }

        const token = await generateSessionToken(email, 'cakto', env);

        return Response.json(
            {
                success: true,
                token: token,
                type: 'cakto',
                expiresIn: 86400
            },
            { headers: corsHeaders }
        );

    } catch (error) {
        return Response.json(
            { error: "Erro interno" },
            { status: 500, headers: corsHeaders }
        );
    }
}

// ============================================================================
// LOGIN ADMIN
// ============================================================================

async function handleAdminLogin(request, env, corsHeaders) {
    try {
        const body = await request.json();
        const username = body.username?.trim();
        const password = body.password;

        if (!username || !password) {
            return Response.json(
                { error: "Usuário e senha obrigatórios" },
                { status: 400, headers: corsHeaders }
            );
        }

        const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
        if (!checkRateLimit(clientIP)) {
            return Response.json(
                { error: "Muitas tentativas. Aguarde um momento." },
                { status: 429, headers: corsHeaders }
            );
        }

        const adminUsers = getAdminUsers(env);
        const passwordHash = await sha256(password);
        
        const validUser = adminUsers.find(user => 
            user.username === username && user.passwordHash === passwordHash
        );
        
        if (!validUser) {
            return Response.json(
                { error: "Credenciais inválidas" },
                { status: 401, headers: corsHeaders }
            );
        }

        const token = await generateSessionToken(username, 'admin', env);

        return Response.json(
            {
                success: true,
                token: token,
                type: 'admin',
                expiresIn: 86400
            },
            { headers: corsHeaders }
        );

    } catch (error) {
        return Response.json(
            { error: "Erro interno" },
            { status: 500, headers: corsHeaders }
        );
    }
}

// ============================================================================
// VERIFY TOKEN
// ============================================================================

async function handleVerifyToken(request, env, corsHeaders) {
    try {
        const body = await request.json();
        const token = body.token;

        if (!token) {
            return Response.json(
                { error: "Token obrigatório" },
                { status: 400, headers: corsHeaders }
            );
        }

        const payload = await verifySessionToken(token, env);

        if (!payload) {
            return Response.json(
                { error: "Token inválido ou expirado" },
                { status: 401, headers: corsHeaders }
            );
        }

        return Response.json(
            {
                valid: true,
                user: payload.user,
                type: payload.type,
                expiresAt: payload.exp
            },
            { headers: corsHeaders }
        );

    } catch (error) {
        return Response.json(
            { error: "Erro interno" },
            { status: 500, headers: corsHeaders }
        );
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

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function checkRateLimit(identifier) {
    const now = Date.now();
    const limit = rateLimitMap.get(identifier);
    
    if (!limit) {
        rateLimitMap.set(identifier, { count: 1, resetAt: now + 60000 });
        return true;
    }
    
    if (now > limit.resetAt) {
        rateLimitMap.set(identifier, { count: 1, resetAt: now + 60000 });
        return true;
    }
    
    if (limit.count >= 10) {
        return false;
    }
    
    limit.count++;
    return true;
}

async function generateSessionToken(user, type, env) {
    const payload = {
        user: user,
        type: type,
        iat: Date.now(),
        exp: Date.now() + 86400000
    };
    
    const payloadStr = JSON.stringify(payload);
    const signature = await sha256(payloadStr + env.SECRET_KEY);
    
    return btoa(payloadStr) + "." + signature;
}

async function verifySessionToken(token, env) {
    try {
        const [payloadB64, signature] = token.split(".");
        const payloadStr = atob(payloadB64);
        const payload = JSON.parse(payloadStr);
        
        if (payload.exp < Date.now()) {
            return null;
        }
        
        const expectedSig = await sha256(payloadStr + env.SECRET_KEY);
        if (signature !== expectedSig) {
            return null;
        }
        
        return payload;
    } catch (_) {
        return null;
    }
}