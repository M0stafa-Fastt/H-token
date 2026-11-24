const crypto = require('crypto');

const ADMIN_COOKIE_NAME = 'htk_admin';
const RL_COOKIE_NAME = 'htk_rl';
const SID_COOKIE_NAME = 'htk_sid';

function sendJson(res, status, payload, extraHeaders = {}) {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');

    for (const [key, value] of Object.entries(extraHeaders)) {
        if (value !== undefined && value !== null) {
            res.setHeader(key, value);
        }
    }
    res.end(JSON.stringify(payload));
}

function parseCookies(req) {
    const out = Object.create(null);
    const header = req && req.headers ? req.headers.cookie : '';
    if (!header || typeof header !== 'string') return out;

    for (const part of header.split(';')) {
        const eqIdx = part.indexOf('=');
        if (eqIdx <= 0) continue;
        const name = part.slice(0, eqIdx).trim();
        if (!name || name === '__proto__' || name === 'constructor' || name === 'prototype') continue;
        const rawVal = part.slice(eqIdx + 1).trim();
        try {
            out[name] = decodeURIComponent(rawVal);
        } catch {
            out[name] = rawVal;
        }
    }
    return out;
}

function isSecureRequest(req) {
    const proto = String((req && req.headers && req.headers['x-forwarded-proto']) || '').toLowerCase();
    return proto === 'https' || Boolean(req && req.socket && req.socket.encrypted);
}

function serializeCookie(name, value, opts = {}) {
    const segments = [`${name}=${encodeURIComponent(String(value || ''))}`];
    segments.push(`Path=${opts.path || '/'}`);
    if (opts.httpOnly !== false) segments.push('HttpOnly');
    segments.push(`SameSite=${opts.sameSite || 'Strict'}`);
    if (typeof opts.maxAge === 'number') {
        segments.push(`Max-Age=${Math.max(0, Math.floor(opts.maxAge))}`);
    }
    if (opts.secure) segments.push('Secure');
    return segments.join('; ');
}

function getClientIp(req) {
    const headers = (req && req.headers) || {};
    const xff = headers['x-forwarded-for'];
    let raw = '';
    if (typeof xff === 'string' && xff.trim()) {
        raw = xff.split(',')[0].trim();
    } else if (typeof headers['x-real-ip'] === 'string' && headers['x-real-ip'].trim()) {
        raw = headers['x-real-ip'].trim();
    } else if (req && req.socket && req.socket.remoteAddress) {
        raw = String(req.socket.remoteAddress).trim();
    }
    if (raw.startsWith('::ffff:')) raw = raw.slice(7);
    const clean = raw.replace(/[^a-zA-Z0-9.:_-]/g, '').toLowerCase().slice(0, 64);
    return clean || 'unknown';
}

function getAdminEnv() {
    const adminUser = typeof process.env.ADMIN_USER === 'string' ? process.env.ADMIN_USER.trim() : '';
    const adminPass = typeof process.env.ADMIN_PASS === 'string' ? process.env.ADMIN_PASS : '';
    return {
        adminUser,
        adminPass,
        configured: Boolean(adminUser && adminPass)
    };
}

function deriveSecret(purpose) {
    const { adminUser, adminPass } = getAdminEnv();
    const root = typeof process.env.AUTH_SECRET === 'string' && process.env.AUTH_SECRET
        ? process.env.AUTH_SECRET
        : `${adminUser}\0${adminPass}\0h_token_vercel_v1`;
    return crypto.createHmac('sha256', String(purpose)).update(root, 'utf8').digest();
}

function timingSafeEqualStrings(a, b, secret) {
    const key = secret || deriveSecret('cmp');
    const ha = crypto.createHmac('sha256', key).update(typeof a === 'string' ? a : '', 'utf8').digest();
    const hb = crypto.createHmac('sha256', key).update(typeof b === 'string' ? b : '', 'utf8').digest();
    return crypto.timingSafeEqual(ha, hb);
}

function signPayload(payload, purpose) {
    const bodyB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const sigB64 = crypto.createHmac('sha256', deriveSecret(purpose)).update(bodyB64, 'utf8').digest('base64url');
    return `${bodyB64}.${sigB64}`;
}

function verifySignedPayload(token, purpose) {
    if (typeof token !== 'string' || !token) return null;
    const dotIdx = token.indexOf('.');
    if (dotIdx <= 0 || dotIdx !== token.lastIndexOf('.')) return null;

    const bodyB64 = token.slice(0, dotIdx);
    const sigB64 = token.slice(dotIdx + 1);
    if (!bodyB64 || !sigB64 || bodyB64.length > 4096 || sigB64.length > 128) return null;

    const expectedSig = crypto.createHmac('sha256', deriveSecret(purpose)).update(bodyB64, 'utf8').digest();
    let providedSig;
    try {
        providedSig = Buffer.from(sigB64, 'base64url');
    } catch {
        return null;
    }
    if (providedSig.length !== expectedSig.length || !crypto.timingSafeEqual(providedSig, expectedSig)) {
        return null;
    }

    try {
        const parsed = JSON.parse(Buffer.from(bodyB64, 'base64url').toString('utf8'));
        return parsed && typeof parsed === 'object' ? parsed : null;
    } catch {
        return null;
    }
}

function extractAdminToken(req) {
    const authHeader = req && req.headers ? req.headers.authorization : '';
    if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
        const bearer = authHeader.slice(7).trim();
        if (bearer) return bearer;
    }
    const cookies = parseCookies(req);
    return cookies[ADMIN_COOKIE_NAME] || '';
}

function verifyAdminRequest(req) {
    const env = getAdminEnv();
    if (!env.configured) return { ok: false };
    const token = extractAdminToken(req);
    const payload = verifySignedPayload(token, 'admin-session');
    if (!payload) return { ok: false };
    if (payload.role !== 'admin' || typeof payload.exp !== 'number' || payload.exp <= Date.now()) {
        return { ok: false };
    }
    const userOk = timingSafeEqualStrings(payload.sub, env.adminUser, deriveSecret('admin-cred-check'));
    if (!userOk) return { ok: false };
    return { ok: true, user: env.adminUser, expiresAt: payload.exp };
}

function createApiError(status, message) {
    const err = new Error(message);
    err.status = status;
    return err;
}

function readRawBody(req, maxBytes = 4718592) {
    if (Buffer.isBuffer(req.rawBody)) {
        if (req.rawBody.length > maxBytes) return Promise.reject(createApiError(413, 'Request payload too large.'));
        return Promise.resolve(req.rawBody);
    }
    if (Buffer.isBuffer(req.body)) {
        if (req.body.length > maxBytes) return Promise.reject(createApiError(413, 'Request payload too large.'));
        return Promise.resolve(req.body);
    }
    if (typeof req.body === 'string' && req.readableEnded) {
        const buf = Buffer.from(req.body, 'latin1');
        if (buf.length > maxBytes) return Promise.reject(createApiError(413, 'Request payload too large.'));
        return Promise.resolve(buf);
    }

    return new Promise((resolve, reject) => {
        const chunks = [];
        let total = 0;
        let done = false;

        req.on('data', chunk => {
            if (done) return;
            const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            total += buf.length;
            if (total > maxBytes) {
                done = true;
                reject(createApiError(413, 'Request payload too large.'));
                if (typeof req.destroy === 'function') req.destroy();
                return;
            }
            chunks.push(buf);
        });
        req.on('end', () => {
            if (done) return;
            done = true;
            resolve(Buffer.concat(chunks, total));
        });
        req.on('error', err => {
            if (done) return;
            done = true;
            reject(createApiError(400, 'Failed to read request body.'));
        });
    });
}

async function readJsonBody(req, maxBytes = 16384) {
    if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
        return req.body;
    }
    if (typeof req.body === 'string') {
        if (Buffer.byteLength(req.body, 'utf8') > maxBytes) {
            throw createApiError(413, 'Request payload too large.');
        }
        try {
            return JSON.parse(req.body);
        } catch {
            throw createApiError(400, 'Invalid JSON body.');
        }
    }
    const raw = await readRawBody(req, maxBytes);
    if (!raw.length) return {};
    try {
        const parsed = JSON.parse(raw.toString('utf8'));
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
    } catch {
        throw createApiError(400, 'Invalid JSON body.');
    }
}

function sanitizeText(val, { maxLen = 120, allowNewlines = false, stripAngles = true } = {}) {
    let str = String(val ?? '').replace(/\r\n?/g, '\n');
    str = str.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069]/g, '');
    if (allowNewlines) {
        str = str.replace(/\n{3,}/g, '\n\n').replace(/[^\S\n]+/g, ' ');
    } else {
        str = str.replace(/\s+/g, ' ');
    }
    if (stripAngles) {
        str = str.replace(/[<>]/g, '');
    }
    return str.trim().slice(0, maxLen);
}

function escapeTelegramHtml(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

module.exports = {
    ADMIN_COOKIE_NAME,
    RL_COOKIE_NAME,
    SID_COOKIE_NAME,
    sendJson,
    parseCookies,
    isSecureRequest,
    serializeCookie,
    getClientIp,
    getAdminEnv,
    deriveSecret,
    timingSafeEqualStrings,
    signPayload,
    verifySignedPayload,
    verifyAdminRequest,
    createApiError,
    readRawBody,
    readJsonBody,
    sanitizeText,
    escapeTelegramHtml
};
