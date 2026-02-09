const rateLimitMap = new Map();
const inMemoryCache = {
    usersList: null,
    usersListExpiresAt: 0
};

export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        const corsHeaders = {
            'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
            'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        };

        try {
            if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders });
            if (url.pathname === "/health") return Response.json({ status: "ok" }, { headers: corsHeaders });
            if (url.pathname === "/webhook/cakto" && request.method === "POST") return handleWebhook(request, env, corsHeaders);
            if (url.pathname === "/cakto/login" && request.method === "POST") return handleCaktoLogin(request, env, corsHeaders);
            if (url.pathname === "/cakto/verify" && request.method === "POST") return handleCaktoVerify(request, env, corsHeaders);
            if (url.pathname === "/cakto/count" && request.method === "GET") return handleCaktoCount(env, corsHeaders);
            if (url.pathname === "/admin/login" && request.method === "POST") return handleAdminLogin(request, env, corsHeaders);
            if (url.pathname === "/verify-token" && request.method === "POST") return handleVerifyToken(request, env, corsHeaders);

            if (url.pathname === "/admin/users" && request.method === "GET") {
                const auth = await requireAdmin(request, env);
                if (!auth.authorized) return Response.json({ error: "Não autorizado" }, { status: 401, headers: corsHeaders });
                const emails = await getUsersFromCache(env);
                return Response.json({ users: emails }, { headers: corsHeaders });
            }

            if (url.pathname === "/cakto/buyers/all" && request.method === "POST") {
                return handleGetAllBuyers(request, env, corsHeaders);
            }

            if (url.pathname === "/cakto/buyers/recent" && request.method === "POST") {
                return handleGetRecentBuyer(request, env, corsHeaders);
            }

            return new Response("Not found", { status: 404, headers: corsHeaders });
        } catch (error) {
            console.error('ERRO CRÍTICO:', error);
            return Response.json({
                error: "Erro crítico",
                message: error.message,
                stack: error.stack
            }, { status: 500, headers: corsHeaders });
        }
    }
};

async function requireAdmin(request, env) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) return { authorized: false };

    const token = authHeader.replace('Bearer ', '');
    const payload = await verifySessionToken(token, env);

    return payload && payload.type === 'admin'
        ? { authorized: true, user: payload.user }
        : { authorized: false };
}

async function requireApiKey(request, env) {
    const apiKey = request.headers.get('X-API-Key');
    
    if (!apiKey) {
        return { authorized: false, error: 'API key obrigatória' };
    }

    // Verificar se a API key é válida
    const validApiKey = env.API_KEY;
    
    if (!validApiKey) {
        console.error('API_KEY não configurada no ambiente');
        return { authorized: false, error: 'Configuração inválida' };
    }

    const apiKeyHash = await sha256(apiKey);
    const validKeyHash = await sha256(validApiKey);
    
    if (apiKeyHash !== validKeyHash) {
        return { authorized: false, error: 'API key inválida' };
    }

    return { authorized: true };
}

// --- CACHE HELPERS ---
async function getUsersFromCache(env) {
    const now = Date.now();
    if (inMemoryCache.usersList && now < inMemoryCache.usersListExpiresAt) {
        return inMemoryCache.usersList;
    }

    // try KV
    try {
        const kvRaw = await env.USERS_KV.get('users_list');
        if (kvRaw) {
            const parsed = JSON.parse(kvRaw);
            inMemoryCache.usersList = parsed;
            inMemoryCache.usersListExpiresAt = now + 60 * 1000; // 1 minuto em memória
            return parsed;
        }
    } catch (e) {
        console.warn('KV get failed', e);
    }

    // fallback to D1 (one-time heavy op when cache cold)
    try {
        const res = await env.DB.prepare("SELECT email FROM users").all();
        const rows = res.results || [];
        const emails = rows.map(r => r.email);
        // store in KV
        try {
            await env.USERS_KV.put('users_list', JSON.stringify(emails), { expirationTtl: 60 * 60 }); // 1h
            await env.USERS_KV.put('users_count', String(emails.length), { expirationTtl: 60 * 60 });
        } catch (e) {
            console.warn('KV put failed', e);
        }
        inMemoryCache.usersList = emails;
        inMemoryCache.usersListExpiresAt = now + 60 * 1000;
        return emails;
    } catch (error) {
        console.error('Erro ao ler D1:', error);
        return [];
    }
}

async function getUsersCountFromCache(env) {
    try {
        const kv = await env.USERS_KV.get('users_count');
        if (kv != null) return Number(kv);
    } catch (e) { /* ignore */ }

    // fallback: derive from cached list, else D1 count (rare)
    const list = await getUsersFromCache(env);
    if (list && list.length) return list.length;

    try {
        const res = await env.DB.prepare("SELECT COUNT(1) as c FROM users").first();
        const c = Number(res?.c || 0);
        try { await env.USERS_KV.put('users_count', String(c), { expirationTtl: 60 * 60 }); } catch {}
        return c;
    } catch (e) {
        console.error('Erro count D1', e);
        return 0;
    }
}

async function addEmail(email, env) {
    if (!email) return false;
    try {
        // sanity
        email = email.toLowerCase().trim();

        // check cache first - avoids a D1 read when cache is hot
        const cached = await getUsersFromCache(env);
        if (cached.includes(email)) {
            return true;
        }

        const now = new Date().toISOString();

        // insert idempotent
        await env.DB.prepare("INSERT OR IGNORE INTO users (email, createdAt) VALUES (?, ?)").bind(email, now).run();

        // update caches: try to update KV list and count atomically-ish
        try {
            // update in-memory
            const updated = Array.isArray(inMemoryCache.usersList) ? inMemoryCache.usersList.slice() : cached.slice();
            if (!updated.includes(email)) updated.push(email);
            inMemoryCache.usersList = updated;
            inMemoryCache.usersListExpiresAt = Date.now() + 60 * 1000;

            // write back to KV (best-effort)
            await env.USERS_KV.put('users_list', JSON.stringify(updated), { expirationTtl: 60 * 60 });
            await env.USERS_KV.put('users_count', String(updated.length), { expirationTtl: 60 * 60 });
        } catch (e) {
            console.warn('KV update failed after insert', e);
        }

        return true;
    } catch (error) {
        console.error('Erro ao adicionar email:', error);
        return false;
    }
}

async function removeEmail(email, env) {
    if (!email) return false;
    try {
        email = email.toLowerCase().trim();

        console.log('Removendo email:', email);

        // invalidate in-memory cache first
        inMemoryCache.usersList = null;
        inMemoryCache.usersListExpiresAt = 0;

        // perform delete
        const deleteResult = await env.DB.prepare("DELETE FROM users WHERE email = ?").bind(email).run();
        console.log('Delete result:', deleteResult);

        // force refresh cache from D1
        const freshList = await env.DB.prepare("SELECT email FROM users").all();
        const emails = (freshList.results || []).map(r => r.email);

        // update all caches
        try {
            inMemoryCache.usersList = emails;
            inMemoryCache.usersListExpiresAt = Date.now() + 60 * 1000;
            await env.USERS_KV.put('users_list', JSON.stringify(emails), { expirationTtl: 60 * 60 });
            await env.USERS_KV.put('users_count', String(emails.length), { expirationTtl: 60 * 60 });
            console.log('Cache atualizado após remoção. Total:', emails.length);
        } catch (e) {
            console.warn('KV update failed after delete', e);
        }

        return true;
    } catch (error) {
        console.error('Erro ao remover email:', error);
        return false;
    }
}

function getAdminUsers(env) {
    try {
        return typeof env.ADMIN_USERS === 'string' ? JSON.parse(env.ADMIN_USERS) : env.ADMIN_USERS;
    } catch { return []; }
}

// ============================================================================
// WEBHOOK
// ============================================================================

async function handleWebhook(request, env, corsHeaders) {
    try {
        const body = await request.json();
        const event = body?.event;
        const email = body?.data?.customer?.email;

        console.log('Webhook recebido:', { event, email });

        if (!email || !isValidEmail(email)) {
            console.error('Email inválido no webhook:', email);
            return Response.json({ error: "Email inválido" }, { status: 400, headers: corsHeaders });
        }

        const addEvents = ["purchase_approved", "subscription_created", "subscription_renewed"];
        const removeEvents = ["subscription_canceled", "subscription_renewal_refused", "refund", "chargeback"];

        if (addEvents.includes(event)) {
            const result = await addEmail(email, env);
            console.log('Email adicionado:', { email, result });
            return Response.json({ success: true, action: 'added', email }, { headers: corsHeaders });
        } else if (removeEvents.includes(event)) {
            const result = await removeEmail(email, env);
            console.log('Email removido:', { email, result });
            return Response.json({ success: true, action: 'removed', email }, { headers: corsHeaders });
        }

        console.log('Evento ignorado:', event);
        return Response.json({ success: true, action: 'ignored', event }, { headers: corsHeaders });
    } catch (error) {
        console.error('Erro no webhook:', error);
        return Response.json({ error: error.message }, { status: 500, headers: corsHeaders });
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
            return Response.json({ error: "Email inválido" }, { status: 400, headers: corsHeaders });
        }

        const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
        if (!checkRateLimit(clientIP)) {
            return Response.json({ error: "Muitas tentativas. Aguarde um momento." }, { status: 429, headers: corsHeaders });
        }

        const emails = await getUsersFromCache(env);
        const isBuyer = Array.isArray(emails) && emails.includes(email);

        if (!isBuyer) return Response.json({ error: "Email não autorizado" }, { status: 403, headers: corsHeaders });

        const token = await generateSessionToken(email, 'cakto', env);
        return Response.json({ success: true, token, type: 'cakto', expiresIn: 86400 }, { headers: corsHeaders });

    } catch {
        return Response.json({ error: "Erro interno" }, { status: 500, headers: corsHeaders });
    }
}

// ============================================================================
// VERIFY CAKTO
// ============================================================================

async function handleCaktoVerify(request, env, corsHeaders) {
    try {
        const body = await request.json();
        const email = body.email?.toLowerCase()?.trim();

        if (!email || !isValidEmail(email)) {
            return Response.json({ error: "Email inválido" }, { status: 400, headers: corsHeaders });
        }

        const emails = await getUsersFromCache(env);
        const isBuyer = Array.isArray(emails) && emails.includes(email);

        return Response.json({ authorized: isBuyer }, { headers: corsHeaders });

    } catch {
        return Response.json({ error: "Erro interno" }, { status: 500, headers: corsHeaders });
    }
}

// ============================================================================
// COUNT CAKTO
// ============================================================================

async function handleCaktoCount(env, corsHeaders) {
    try {
        const count = await getUsersCountFromCache(env);
        return Response.json({ count }, { headers: corsHeaders });
    } catch {
        return Response.json({ error: "Erro interno" }, { status: 500, headers: corsHeaders });
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
            return Response.json({ error: "Usuário e senha obrigatórios" }, { status: 400, headers: corsHeaders });
        }

        const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
        if (!checkRateLimit(clientIP)) {
            return Response.json({ error: "Muitas tentativas. Aguarde um momento." }, { status: 429, headers: corsHeaders });
        }

        const adminUsers = getAdminUsers(env);
        const passwordHash = await sha256(password);
        const validUser = adminUsers.find(u => u.username === username && u.passwordHash === passwordHash);
        
        if (!validUser) return Response.json({ error: "Credenciais inválidas" }, { status: 401, headers: corsHeaders });

        const token = await generateSessionToken(username, 'admin', env);
        return Response.json({ success: true, token, type: 'admin', expiresIn: 86400 }, { headers: corsHeaders });

    } catch {
        return Response.json({ error: "Erro interno" }, { status: 500, headers: corsHeaders });
    }
}

// ============================================================================
// VERIFY TOKEN
// ============================================================================

async function handleVerifyToken(request, env, corsHeaders) {
    try {
        const body = await request.json();
        const token = body.token;

        if (!token) return Response.json({ error: "Token obrigatório" }, { status: 400, headers: corsHeaders });

        const payload = await verifySessionToken(token, env);
        if (!payload) return Response.json({ error: "Token inválido ou expirado" }, { status: 401, headers: corsHeaders });

        return Response.json({ valid: true, user: payload.user, type: payload.type, expiresAt: payload.exp }, { headers: corsHeaders });

    } catch {
        return Response.json({ error: "Erro interno" }, { status: 500, headers: corsHeaders });
    }
}

// ============================================================================
// GET ALL BUYERS
// ============================================================================

async function handleGetAllBuyers(request, env, corsHeaders) {
    try {
        // Verificar API key 
        /*
        const auth = await requireApiKey(request, env);
        if (!auth.authorized) {
            return Response.json({ 
                error: auth.error || "Não autorizado" 
            }, { status: 401, headers: corsHeaders });
        }
        */

        const res = await env.DB.prepare("SELECT email, createdAt FROM users ORDER BY createdAt DESC").all();
        const buyers = (res.results || []).map(row => ({
            email: row.email,
            createdAt: row.createdAt
        }));
        
        return Response.json({ 
            success: true, 
            total: buyers.length,
            buyers 
        }, { headers: corsHeaders });
    } catch (error) {
        console.error('Erro ao buscar compradores:', error);
        return Response.json({ error: "Erro interno" }, { status: 500, headers: corsHeaders });
    }
}

// ============================================================================
// GET RECENT BUYER
// ============================================================================

async function handleGetRecentBuyer(request, env, corsHeaders) {
    try {
        // Verificar API key
        /*
        const auth = await requireApiKey(request, env);
        if (!auth.authorized) {
            return Response.json({ 
                error: auth.error || "Não autorizado" 
            }, { status: 401, headers: corsHeaders });
        }
        */
        
        const res = await env.DB.prepare("SELECT email, createdAt FROM users ORDER BY createdAt DESC LIMIT 1").first();
        
        if (!res) {
            return Response.json({ 
                success: true, 
                buyer: null 
            }, { headers: corsHeaders });
        }

        return Response.json({ 
            success: true, 
            buyer: {
                email: res.email,
                createdAt: res.createdAt
            }
        }, { headers: corsHeaders });
    } catch (error) {
        console.error('Erro ao buscar comprador recente:', error);
        return Response.json({ error: "Erro interno" }, { status: 500, headers: corsHeaders });
    }
}

// ============================================================================
// HELPERS
// ============================================================================

async function sha256(text) {
    const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function checkRateLimit(identifier) {
    const now = Date.now();
    const limit = rateLimitMap.get(identifier);
    
    if (!limit || now > limit.resetAt) {
        rateLimitMap.set(identifier, { count: 1, resetAt: now + 60000 });
        return true;
    }
    
    if (limit.count >= 10) return false;
    
    limit.count++;
    return true;
}

async function generateSessionToken(user, type, env) {
    const payload = { user, type, iat: Date.now(), exp: Date.now() + 86400000 };
    const payloadStr = JSON.stringify(payload);
    const signature = await sha256(payloadStr + env.SECRET_KEY);
    return btoa(payloadStr) + "." + signature;
}

async function verifySessionToken(token, env) {
    try {
        const [payloadB64, signature] = token.split(".");
        const payloadStr = atob(payloadB64);
        const payload = JSON.parse(payloadStr);
        
        if (payload.exp < Date.now()) return null;
        
        const expectedSig = await sha256(payloadStr + env.SECRET_KEY);
        return signature === expectedSig ? payload : null;
    } catch { return null; }
}


