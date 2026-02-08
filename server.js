import { MongoClient } from 'mongodb';

const rateLimitMap = new Map();
let client = null;

export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        const corsHeaders = {
            'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN || '*',
            'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        };

        try {
            if (!client) {
                console.log('Conectando ao MongoDB...');
                client = new MongoClient(env.MONGO_URI, {
                    maxPoolSize: 1,
                    minPoolSize: 0,
                    serverSelectionTimeoutMS: 5000,
                });
                await client.connect();
                console.log('MongoDB conectado!');
            }

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
                const emails = await getRemoteData(env);
                return Response.json({ users: emails }, { headers: corsHeaders });
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

function getCollection(env) {
    const db = client.db(env.MONGO_DATABASE || 'cakto');
    return db.collection('users');
}

async function getRemoteData(env) {
    try {
        console.log('Buscando dados no MongoDB...');
        const collection = getCollection(env);
        const users = await collection.find({}).toArray();
        console.log('Dados encontrados:', users.length);
        return users.map(u => u.email);
    } catch (error) {
        console.error('Erro ao buscar dados:', error);
        return [];
    }
}

async function addEmail(email, env) {
    if (!email) return false;
    try {
        console.log('Adicionando email:', email);
        const collection = getCollection(env);
        const existing = await collection.findOne({ email });
        if (existing) {
            console.log('Email já existe');
            return true;
        }
        const result = await collection.insertOne({ email, createdAt: new Date() });
        console.log('Email inserido:', result.insertedId);
        return true;
    } catch (error) {
        console.error('Erro ao adicionar email:', error);
        return false;
    }
}

async function removeEmail(email, env) {
    if (!email) return false;
    try {
        console.log('Removendo email:', email);
        const collection = getCollection(env);
        const result = await collection.deleteOne({ email });
        console.log('Email removido:', result.deletedCount);
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

async function handleWebhook(request, env, corsHeaders) {
    try {
        console.log('Webhook recebido');
        const body = await request.json();
        console.log('Webhook body:', JSON.stringify(body));
        
        const event = body?.event;
        const email = body?.data?.customer?.email;

        console.log('Event:', event, 'Email:', email);

        const addEvents = ["purchase_approved", "subscription_created", "subscription_renewed"];
        const removeEvents = ["subscription_canceled", "subscription_renewal_refused", "refund", "chargeback"];

        if (addEvents.includes(event)) {
            const success = await addEmail(email, env);
            console.log('Adicionar email success:', success);
        } else if (removeEvents.includes(event)) {
            const success = await removeEmail(email, env);
            console.log('Remover email success:', success);
        }

        return Response.json({ success: true }, { headers: corsHeaders });
    } catch (error) {
        console.error('Erro no webhook:', error);
        return Response.json({ error: error.message, stack: error.stack }, { status: 500, headers: corsHeaders });
    }
}

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

        const collection = getCollection(env);
        const userDoc = await collection.findOne({ email });
        const isBuyer = !!userDoc;

        if (!isBuyer) return Response.json({ error: "Email não autorizado" }, { status: 403, headers: corsHeaders });

        const token = await generateSessionToken(email, 'cakto', env);
        return Response.json({ success: true, token, type: 'cakto', expiresIn: 86400 }, { headers: corsHeaders });

    } catch (error) {
        console.error('Erro no login:', error);
        return Response.json({ error: "Erro interno", message: error.message }, { status: 500, headers: corsHeaders });
    }
}

async function handleCaktoVerify(request, env, corsHeaders) {
    try {
        const body = await request.json();
        const email = body.email?.toLowerCase()?.trim();

        if (!email || !isValidEmail(email)) {
            return Response.json({ error: "Email inválido" }, { status: 400, headers: corsHeaders });
        }

        const collection = getCollection(env);
        const userDoc = await collection.findOne({ email });
        const isBuyer = !!userDoc;

        return Response.json({ authorized: isBuyer }, { headers: corsHeaders });

    } catch (error) {
        console.error('Erro no verify:', error);
        return Response.json({ error: "Erro interno", message: error.message }, { status: 500, headers: corsHeaders });
    }
}

async function handleCaktoCount(env, corsHeaders) {
    try {
        console.log('Count requisitado');
        const collection = getCollection(env);
        const count = await collection.countDocuments();
        console.log('Count:', count);
        return Response.json({ count }, { headers: corsHeaders });
    } catch (error) {
        console.error('Erro no count:', error);
        return Response.json({ error: "Erro interno", message: error.message, stack: error.stack }, { status: 500, headers: corsHeaders });
    }
}

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

    } catch (error) {
        console.error('Erro no admin login:', error);
        return Response.json({ error: "Erro interno", message: error.message }, { status: 500, headers: corsHeaders });
    }
}

async function handleVerifyToken(request, env, corsHeaders) {
    try {
        const body = await request.json();
        const token = body.token;

        if (!token) return Response.json({ error: "Token obrigatório" }, { status: 400, headers: corsHeaders });

        const payload = await verifySessionToken(token, env);
        if (!payload) return Response.json({ error: "Token inválido ou expirado" }, { status: 401, headers: corsHeaders });

        return Response.json({ valid: true, user: payload.user, type: payload.type, expiresAt: payload.exp }, { headers: corsHeaders });

    } catch (error) {
        console.error('Erro no verify token:', error);
        return Response.json({ error: "Erro interno", message: error.message }, { status: 500, headers: corsHeaders });
    }
}

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
