const crypto = require('crypto');
const {
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
    readJsonBody
} = require('./_auth');

const MAX_ATTEMPTS = 3;
const BLOCK_DURATION_MS = 15 * 60 * 1000;
const BLOCK_DURATION_SEC = Math.ceil(BLOCK_DURATION_MS / 1000);
const ADMIN_SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const ADMIN_SESSION_TTL_SEC = Math.ceil(ADMIN_SESSION_TTL_MS / 1000);

const attemptStore = globalThis.__hTokenLoginAttempts || (globalThis.__hTokenLoginAttempts = new Map());

function pruneAttemptStore(now) {
    if (attemptStore.size < 200) return;
    for (const [key, rec] of attemptStore.entries()) {
        if (!rec || (rec.lockedUntil && now > rec.lockedUntil) || (!rec.lockedUntil && now - rec.lastAttempt > BLOCK_DURATION_MS)) {
            attemptStore.delete(key);
        }
    }
}

function readBucket(key, now) {
    const rec = attemptStore.get(key);
    if (!rec) return { fails: 0, lockedUntil: 0, lastAttempt: 0 };
    if (rec.lockedUntil && now >= rec.lockedUntil) {
        attemptStore.delete(key);
        return { fails: 0, lockedUntil: 0, lastAttempt: 0 };
    }
    if (!rec.lockedUntil && now - rec.lastAttempt > BLOCK_DURATION_MS) {
        attemptStore.delete(key);
        return { fails: 0, lockedUntil: 0, lastAttempt: 0 };
    }
    return rec;
}

function readSignedRlCookie(rawCookie, now) {
    const parsed = verifySignedPayload(rawCookie, 'login-rl');
    if (!parsed || typeof parsed.exp !== 'number' || parsed.exp <= now) {
        return { fails: 0, lockedUntil: 0 };
    }
    const maxAllowedUntil = now + BLOCK_DURATION_MS + 1000;
    const lockedUntil = typeof parsed.lockedUntil === 'number' && parsed.lockedUntil > now
        ? Math.min(parsed.lockedUntil, maxAllowedUntil)
        : 0;
    const fails = typeof parsed.fails === 'number' && parsed.fails > 0 ? Math.min(parsed.fails, 100) : 0;
    return { fails, lockedUntil };
}

function resolveSessionId(req, cookies) {
    const cookieSid = String(cookies[SID_COOKIE_NAME] || '').trim();
    if (/^[a-f0-9]{16,64}$/i.test(cookieSid)) {
        return cookieSid.toLowerCase();
    }
    const hdrSid = String((req.headers && req.headers['x-client-session']) || '').trim();
    if (/^[a-f0-9]{16,64}$/i.test(hdrSid)) {
        return hdrSid.toLowerCase();
    }
    return crypto.randomBytes(16).toString('hex');
}

module.exports = async function handler(req, res) {
    const method = String(req.method || 'GET').toUpperCase();
    const secure = isSecureRequest(req);

    if (method === 'GET') {
        const auth = verifyAdminRequest(req);
        if (!auth.ok) {
            return sendJson(res, 401, { ok: false, authenticated: false });
        }
        return sendJson(res, 200, {
            ok: true,
            authenticated: true,
            user: auth.user,
            expiresAt: auth.expiresAt
        });
    }

    if (method === 'DELETE') {
        return sendJson(res, 200, { ok: true }, {
            'Set-Cookie': [
                serializeCookie(ADMIN_COOKIE_NAME, '', { maxAge: 0, secure })
            ]
        });
    }

    if (method !== 'POST') {
        return sendJson(res, 405, { ok: false, error: 'Method Not Allowed.' }, { Allow: 'GET, POST, DELETE' });
    }

    const env = getAdminEnv();
    if (!env.configured) {
        return sendJson(res, 500, {
            ok: false,
            error: 'Admin environment variables (ADMIN_USER / ADMIN_PASS) are not configured on the server.'
        });
    }

    const now = Date.now();
    pruneAttemptStore(now);

    const clientIp = getClientIp(req);
    const cookies = parseCookies(req);
    const sid = resolveSessionId(req, cookies);
    const ipKey = `ip:${clientIp}`;
    const sidKey = `sid:${sid}`;

    const ipRec = readBucket(ipKey, now);
    const sidRec = readBucket(sidKey, now);
    const cookieRec = readSignedRlCookie(cookies[RL_COOKIE_NAME], now);

    const activeLockedUntil = Math.max(ipRec.lockedUntil || 0, sidRec.lockedUntil || 0, cookieRec.lockedUntil || 0);
    const activeFails = Math.max(ipRec.fails || 0, sidRec.fails || 0, cookieRec.fails || 0);

    const sidCookieHeader = serializeCookie(SID_COOKIE_NAME, sid, { maxAge: 7 * 24 * 3600, secure });

    if (activeLockedUntil > now) {
        const retryAfterSeconds = Math.max(1, Math.ceil((activeLockedUntil - now) / 1000));
        const lockState = { fails: Math.max(activeFails, MAX_ATTEMPTS), lockedUntil: activeLockedUntil, lastAttempt: now };
        attemptStore.set(ipKey, lockState);
        attemptStore.set(sidKey, lockState);

        const signedRl = signPayload({
            fails: lockState.fails,
            lockedUntil: activeLockedUntil,
            iat: now,
            exp: activeLockedUntil
        }, 'login-rl');

        return sendJson(res, 429, {
            ok: false,
            locked: true,
            attemptsRemaining: 0,
            retryAfterSeconds,
            lockedUntil: activeLockedUntil,
            error: 'Too many failed login attempts. Blocked for 15 minutes.'
        }, {
            'Retry-After': String(retryAfterSeconds),
            'Set-Cookie': [
                sidCookieHeader,
                serializeCookie(RL_COOKIE_NAME, signedRl, { maxAge: retryAfterSeconds, secure })
            ]
        });
    }

    let body;
    try {
        body = await readJsonBody(req, 16384);
    } catch (err) {
        return sendJson(res, err.status || 400, { ok: false, error: err.message || 'Invalid request body.' });
    }

    const username = typeof body.username === 'string' ? body.username.replace(/[\u0000-\u001F\u007F]/g, '').trim() : '';
    const password = typeof body.password === 'string' ? body.password.replace(/\u0000/g, '') : '';

    if (!username || !password || username.length > 128 || password.length > 256) {
        return sendJson(res, 400, { ok: false, error: 'Username and password are required.' }, {
            'Set-Cookie': [sidCookieHeader]
        });
    }

    const credSecret = deriveSecret('admin-cred-check');
    const userMatch = timingSafeEqualStrings(username, env.adminUser, credSecret);
    const passMatch = timingSafeEqualStrings(password, env.adminPass, credSecret);
    const isMatch = Boolean(userMatch & passMatch);

    if (!isMatch) {
        const nextFails = activeFails + 1;
        const isNowLocked = nextFails >= MAX_ATTEMPTS;
        const lockedUntil = isNowLocked ? now + BLOCK_DURATION_MS : 0;
        const nextState = { fails: nextFails, lockedUntil, lastAttempt: now };
        attemptStore.set(ipKey, nextState);
        attemptStore.set(sidKey, nextState);

        const exp = isNowLocked ? lockedUntil : now + BLOCK_DURATION_MS;
        const signedRl = signPayload({ fails: nextFails, lockedUntil, iat: now, exp }, 'login-rl');
        const cookiesOut = [
            sidCookieHeader,
            serializeCookie(RL_COOKIE_NAME, signedRl, { maxAge: BLOCK_DURATION_SEC, secure })
        ];

        if (isNowLocked) {
            return sendJson(res, 429, {
                ok: false,
                locked: true,
                attemptsRemaining: 0,
                retryAfterSeconds: BLOCK_DURATION_SEC,
                lockedUntil,
                error: 'Too many failed login attempts. Blocked for 15 minutes.'
            }, {
                'Retry-After': String(BLOCK_DURATION_SEC),
                'Set-Cookie': cookiesOut
            });
        }

        return sendJson(res, 401, {
            ok: false,
            locked: false,
            attemptsRemaining: Math.max(0, MAX_ATTEMPTS - nextFails),
            error: 'Invalid admin username or password.'
        }, {
            'Set-Cookie': cookiesOut
        });
    }

    attemptStore.delete(ipKey);
    attemptStore.delete(sidKey);

    const expiresAt = now + ADMIN_SESSION_TTL_MS;
    const token = signPayload({
        sub: env.adminUser,
        role: 'admin',
        iat: now,
        exp: expiresAt,
        jti: crypto.randomBytes(12).toString('hex')
    }, 'admin-session');

    return sendJson(res, 200, {
        ok: true,
        token,
        user: env.adminUser,
        expiresAt
    }, {
        'Set-Cookie': [
            sidCookieHeader,
            serializeCookie(RL_COOKIE_NAME, '', { maxAge: 0, secure }),
            serializeCookie(ADMIN_COOKIE_NAME, token, { maxAge: ADMIN_SESSION_TTL_SEC, secure })
        ]
    });
};
