const crypto = require('crypto');
const {
    sendJson,
    verifyAdminRequest,
    createApiError,
    readJsonBody,
    sanitizeText
} = require('./_auth');

const KV_KEY = 'h_token_db_v1';
const USER_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_STORED_TXT_CHARS = 50000;
const MAX_JSON_BODY_BYTES = 512 * 1024;

function randomHex(bytesLen = 16) {
    return crypto.randomBytes(bytesLen).toString('hex');
}

function genId() {
    return Date.now().toString(36) + randomHex(4);
}

function defaultDb() {
    return {
        users: [],
        sessions: [],
        submissions: [],
        hwids: [],
        vortexKeys: []
    };
}

function getKvConfig() {
    const restUrl = String(process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '')
        .trim()
        .replace(/\/+$/, '');
    const restToken = String(process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '').trim();
    return { restUrl, restToken, configured: Boolean(restUrl && restToken) };
}

async function kvCommand(cmdArgs) {
    const { restUrl, restToken, configured } = getKvConfig();
    if (!configured) {
        throw createApiError(500, 'KV database environment variables (KV_REST_API_URL / KV_REST_API_TOKEN) are not configured.');
    }

    let resp;
    try {
        resp = await fetch(restUrl, {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${restToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(cmdArgs)
        });
    } catch {
        throw createApiError(502, 'Could not reach KV REST endpoint.');
    }

    const data = await resp.json().catch(() => null);
    if (!resp.ok || !data || data.error) {
        console.error('KV REST command failed:', cmdArgs[0], resp.status, data && data.error);
        throw createApiError(502, 'Database storage error.');
    }
    return data.result;
}

async function loadKvDb() {
    const raw = await kvCommand(['GET', KV_KEY]);
    if (!raw || typeof raw !== 'string') {
        return defaultDb();
    }
    try {
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== 'object') return defaultDb();
        return {
            users: Array.isArray(parsed.users) ? parsed.users : [],
            sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
            submissions: Array.isArray(parsed.submissions) ? parsed.submissions : [],
            hwids: Array.isArray(parsed.hwids) ? parsed.hwids : [],
            vortexKeys: Array.isArray(parsed.vortexKeys) ? parsed.vortexKeys : []
        };
    } catch {
        return defaultDb();
    }
}

async function saveKvDb(db) {
    const now = Date.now();
    db.sessions = (db.sessions || []).filter(s => s && s.role === 'user' && s.expiresAt > now);
    await kvCommand(['SET', KV_KEY, JSON.stringify(db)]);
}

function hashUserPassword(password) {
    const salt = randomHex(16);
    const derived = crypto.scryptSync(String(password), salt, 32).toString('hex');
    return `scrypt$${salt}$${derived}`;
}

function verifyUserPassword(password, stored) {
    const raw = String(stored || '');
    if (raw.startsWith('scrypt$')) {
        const parts = raw.split('$');
        if (parts.length !== 3) return false;
        const [, salt, expectedHex] = parts;
        if (!salt || !expectedHex) return false;
        let expectedBuf;
        try {
            expectedBuf = Buffer.from(expectedHex, 'hex');
        } catch {
            return false;
        }
        const actualBuf = crypto.scryptSync(String(password), salt, 32);
        return expectedBuf.length === actualBuf.length && crypto.timingSafeEqual(actualBuf, expectedBuf);
    }

    // Legacy 64-round salted SHA-256 support
    const legacyParts = raw.split(':');
    if (legacyParts.length !== 2) return false;
    const [salt, expectedHex] = legacyParts;
    if (!salt || !expectedHex) return false;
    let acc = `${salt}:${password}`;
    for (let i = 0; i < 64; i++) {
        acc = crypto.createHash('sha256').update(`${salt}:${acc}`, 'utf8').digest('hex');
    }
    let expectedBuf;
    let actualBuf;
    try {
        expectedBuf = Buffer.from(expectedHex, 'hex');
        actualBuf = Buffer.from(acc, 'hex');
    } catch {
        return false;
    }
    return expectedBuf.length === actualBuf.length && crypto.timingSafeEqual(actualBuf, expectedBuf);
}

function createUserSession(db, userId) {
    const token = randomHex(24);
    db.sessions.push({
        token,
        role: 'user',
        userId,
        createdAt: new Date().toISOString(),
        expiresAt: Date.now() + USER_SESSION_TTL_MS
    });
    return token;
}

function extractBearerToken(req) {
    const authHeader = req && req.headers ? req.headers.authorization : '';
    if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
        return authHeader.slice(7).trim();
    }
    return '';
}

function getUserSession(db, token) {
    if (!token) return null;
    const now = Date.now();
    const session = db.sessions.find(s => s && s.token === token && s.role === 'user' && s.expiresAt > now);
    if (!session) return null;
    const user = db.users.find(u => u && u.id === session.userId);
    return user ? { session, user } : null;
}

function publicUser(user) {
    return {
        id: user.id,
        name: user.name,
        username: user.username,
        createdAt: user.createdAt
    };
}

function safeDecodeParam(val) {
    try {
        return decodeURIComponent(String(val || ''));
    } catch {
        return String(val || '');
    }
}

function sanitizeTxtFileName(rawName) {
    const base = String(rawName || '')
        .split(/[\\/]/)
        .pop()
        .replace(/[\u0000-\u001F\u007F<>:"|?*]/g, '')
        .replace(/\.\.+/g, '.')
        .trim();
    if (!/\.txt$/i.test(base)) return 'report.txt';
    const stem = base.slice(0, -4).replace(/^\.+/, '').slice(0, 100) || 'report';
    return `${stem}.txt`;
}

function resolveRouteUrl(req) {
    const urlObj = new URL(req.url || '/', 'http://localhost');
    const rawRoute = urlObj.searchParams.get('__route');
    let pathname = rawRoute ? rawRoute : urlObj.pathname;
    if (!pathname.startsWith('/')) pathname = '/' + pathname;
    pathname = pathname.replace(/\/+$/, '') || '/';
    return { pathname, searchParams: urlObj.searchParams };
}

module.exports = async function handler(req, res) {
    const method = String(req.method || 'GET').toUpperCase();
    const { pathname, searchParams } = resolveRouteUrl(req);
    const token = extractBearerToken(req);

    let body = {};
    if (method === 'POST' || method === 'PATCH' || method === 'PUT') {
        try {
            body = await readJsonBody(req, MAX_JSON_BODY_BYTES);
        } catch (err) {
            return sendJson(res, err.status || 400, { ok: false, error: err.message || 'تنسيق البيانات غير صالح.' });
        }
    }

    try {
        // --- Admin Protected Endpoints ---
        if (pathname.startsWith('/api/admin/')) {
            const adminAuth = verifyAdminRequest(req);
            if (!adminAuth.ok) {
                return sendJson(res, 401, { ok: false, error: 'انتهت جلسة الأدمن أو غير مصرح.' });
            }

            const db = await loadKvDb();

            if (pathname === '/api/admin/submissions' && method === 'GET') {
                return sendJson(res, 200, { submissions: db.submissions });
            }

            if (pathname === '/api/admin/submissions' && method === 'DELETE') {
                db.submissions = [];
                await saveKvDb(db);
                return sendJson(res, 200, { ok: true });
            }

            const subMatch = pathname.match(/^\/api\/admin\/submissions\/([^/]+)$/);
            if (subMatch && method === 'DELETE') {
                const id = safeDecodeParam(subMatch[1]);
                db.submissions = db.submissions.filter(s => s.id !== id);
                await saveKvDb(db);
                return sendJson(res, 200, { ok: true });
            }

            if (pathname === '/api/admin/hwids' && method === 'GET') {
                return sendJson(res, 200, { hwids: db.hwids });
            }

            const hwidMatch = pathname.match(/^\/api\/admin\/hwids\/([^/]+)$/);
            if (hwidMatch && method === 'PATCH') {
                const id = safeDecodeParam(hwidMatch[1]);
                const nextStatus = String(body.status || '');
                if (!['pending', 'active', 'rejected'].includes(nextStatus)) {
                    return sendJson(res, 400, { ok: false, error: 'حالة غير صالحة.' });
                }
                const item = db.hwids.find(h => h.id === id);
                if (!item) {
                    return sendJson(res, 404, { ok: false, error: 'الطلب غير موجود.' });
                }
                item.status = nextStatus;
                item.updatedAt = new Date().toISOString();
                await saveKvDb(db);
                return sendJson(res, 200, { ok: true, record: item });
            }

            if (hwidMatch && method === 'DELETE') {
                const id = safeDecodeParam(hwidMatch[1]);
                db.hwids = db.hwids.filter(h => h.id !== id);
                await saveKvDb(db);
                return sendJson(res, 200, { ok: true });
            }

            if (pathname === '/api/admin/vortex' && method === 'GET') {
                return sendJson(res, 200, { keys: db.vortexKeys });
            }

            if (pathname === '/api/admin/vortex' && method === 'POST') {
                const rawLines = Array.isArray(body.keys)
                    ? body.keys
                    : String(body.keysText || '').split(/[\r\n,]+/);
                const existingSet = new Set(db.vortexKeys.map(k => k.key));
                let addedCount = 0;
                let skippedDuplicates = 0;

                for (const raw of rawLines) {
                    const key = sanitizeText(raw, { maxLen: 200, stripAngles: true });
                    if (!key) continue;
                    if (existingSet.has(key)) {
                        skippedDuplicates++;
                        continue;
                    }
                    existingSet.add(key);
                    db.vortexKeys.push({
                        id: genId(),
                        key,
                        status: 'available',
                        createdAt: new Date().toISOString(),
                        claimedByUserId: null,
                        claimedByName: '',
                        claimedByUsername: '',
                        claimedAt: null
                    });
                    addedCount++;
                }

                if (addedCount === 0 && skippedDuplicates === 0) {
                    return sendJson(res, 400, { ok: false, error: 'يرجى إدخال كيي واحد على الأقل.' });
                }
                await saveKvDb(db);
                return sendJson(res, 200, { ok: true, addedCount, skippedDuplicates, keys: db.vortexKeys });
            }

            if (pathname === '/api/admin/vortex' && method === 'DELETE') {
                const scope = String(searchParams.get('scope') || 'all');
                db.vortexKeys = scope === 'available'
                    ? db.vortexKeys.filter(k => k.status !== 'available')
                    : [];
                await saveKvDb(db);
                return sendJson(res, 200, { ok: true, keys: db.vortexKeys });
            }

            const vortexMatch = pathname.match(/^\/api\/admin\/vortex\/([^/]+)$/);
            if (vortexMatch && method === 'DELETE') {
                const id = safeDecodeParam(vortexMatch[1]);
                db.vortexKeys = db.vortexKeys.filter(k => k.id !== id);
                await saveKvDb(db);
                return sendJson(res, 200, { ok: true });
            }

            if (pathname === '/api/admin/users' && method === 'GET') {
                const now = Date.now();
                const users = db.users.map(u => {
                    const userSubs = db.submissions.filter(s => s.userId === u.id);
                    const userHwids = db.hwids.filter(h => h.userId === u.id);
                    const activeSessions = db.sessions.filter(
                        s => s.role === 'user' && s.userId === u.id && s.expiresAt > now
                    ).length;
                    return {
                        id: u.id,
                        name: u.name,
                        username: u.username,
                        createdAt: u.createdAt,
                        lastLoginAt: u.lastLoginAt || null,
                        hasActiveSession: activeSessions > 0,
                        activeSessions,
                        submissionsCount: userSubs.length,
                        totalValid: userSubs.reduce((acc, s) => acc + (typeof s.valid === 'number' ? s.valid : 0), 0),
                        totalMailLocked: userSubs.reduce((acc, s) => acc + (typeof s.mailLocked === 'number' ? s.mailLocked : 0), 0),
                        lastSubmissionAt: userSubs[0] ? userSubs[0].createdAt : null,
                        lastSubmissionAr: userSubs[0] ? userSubs[0].timestampAr : '',
                        hwidsCount: userHwids.length
                    };
                }).sort((a, b) => String(b.lastLoginAt || b.createdAt).localeCompare(String(a.lastLoginAt || a.createdAt)));
                return sendJson(res, 200, { users });
            }

            const userPassMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)\/password$/);
            if (userPassMatch && method === 'PATCH') {
                const id = safeDecodeParam(userPassMatch[1]);
                const newPassword = String(body.password || '').replace(/\u0000/g, '');
                if (newPassword.length < 4 || newPassword.length > 128) {
                    return sendJson(res, 400, { ok: false, error: 'كلمة المرور الجديدة يجب أن تكون 4 أحرف على الأقل.' });
                }
                const user = db.users.find(u => u.id === id);
                if (!user) {
                    return sendJson(res, 404, { ok: false, error: 'المستخدم غير موجود.' });
                }
                user.passwordHash = hashUserPassword(newPassword);
                await saveKvDb(db);
                return sendJson(res, 200, { ok: true });
            }

            const userLogoutMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)\/logout$/);
            if (userLogoutMatch && method === 'POST') {
                const id = safeDecodeParam(userLogoutMatch[1]);
                db.sessions = db.sessions.filter(s => !(s.role === 'user' && s.userId === id));
                await saveKvDb(db);
                return sendJson(res, 200, { ok: true });
            }

            const userDelMatch = pathname.match(/^\/api\/admin\/users\/([^/]+)$/);
            if (userDelMatch && method === 'DELETE') {
                const id = safeDecodeParam(userDelMatch[1]);
                db.users = db.users.filter(u => u.id !== id);
                db.sessions = db.sessions.filter(s => !(s.role === 'user' && s.userId === id));
                await saveKvDb(db);
                return sendJson(res, 200, { ok: true });
            }

            return sendJson(res, 404, { ok: false, error: 'المسار غير موجود.' });
        }

        // --- User Auth Endpoints ---
        if (pathname === '/api/auth/register' && method === 'POST') {
            const name = sanitizeText(body.name, { maxLen: 60 });
            const username = sanitizeText(body.username, { maxLen: 32 }).toLowerCase();
            const password = String(body.password || '').replace(/\u0000/g, '');

            if (name.length < 2 || name.length > 60) {
                return sendJson(res, 400, { ok: false, error: 'الاسم يجب أن يكون من 2 إلى 60 حرفاً.' });
            }
            if (!/^[a-z0-9_.-]{3,32}$/.test(username)) {
                return sendJson(res, 400, { ok: false, error: 'اسم المستخدم يجب أن يكون بالإنجليزية (3 إلى 32 حرف/رقم بدون مسافات).' });
            }
            if (password.length < 4 || password.length > 128) {
                return sendJson(res, 400, { ok: false, error: 'كلمة المرور يجب أن تكون 4 أحرف على الأقل.' });
            }

            const db = await loadKvDb();
            if (db.users.some(u => u.username === username)) {
                return sendJson(res, 409, { ok: false, error: 'اسم المستخدم مسجل بالفعل، اختر اسماً آخر.' });
            }

            const nowIso = new Date().toISOString();
            const user = {
                id: genId(),
                name,
                username,
                passwordHash: hashUserPassword(password),
                createdAt: nowIso,
                lastLoginAt: nowIso
            };
            db.users.push(user);
            const newToken = createUserSession(db, user.id);
            await saveKvDb(db);
            return sendJson(res, 200, { token: newToken, user: publicUser(user) });
        }

        if (pathname === '/api/auth/login' && method === 'POST') {
            const username = sanitizeText(body.username, { maxLen: 32 }).toLowerCase();
            const password = String(body.password || '').replace(/\u0000/g, '');
            const db = await loadKvDb();
            const user = db.users.find(u => u.username === username);
            if (!user || !verifyUserPassword(password, user.passwordHash)) {
                return sendJson(res, 401, { ok: false, error: 'اسم المستخدم أو كلمة المرور غير صحيحة.' });
            }
            user.lastLoginAt = new Date().toISOString();
            const newToken = createUserSession(db, user.id);
            await saveKvDb(db);
            return sendJson(res, 200, { token: newToken, user: publicUser(user) });
        }

        if (pathname === '/api/auth/me' && method === 'GET') {
            const db = await loadKvDb();
            const auth = getUserSession(db, token);
            if (!auth) {
                return sendJson(res, 401, { ok: false, error: 'غير مسجل الدخول.' });
            }
            if (!auth.user.lastLoginAt) {
                auth.user.lastLoginAt = auth.session.createdAt || auth.user.createdAt;
                await saveKvDb(db);
            }
            return sendJson(res, 200, { user: publicUser(auth.user) });
        }

        if (pathname === '/api/auth/logout' && method === 'POST') {
            if (token) {
                const db = await loadKvDb();
                db.sessions = db.sessions.filter(s => s.token !== token);
                await saveKvDb(db);
            }
            return sendJson(res, 200, { ok: true });
        }

        // --- User Submissions ---
        if (pathname === '/api/submissions/mine' && method === 'GET') {
            const db = await loadKvDb();
            const auth = getUserSession(db, token);
            if (!auth) {
                return sendJson(res, 401, { ok: false, error: 'يرجى تسجيل الدخول أولاً.' });
            }
            const mine = db.submissions.filter(s => s.userId === auth.user.id);
            const totalValid = mine.reduce((acc, s) => acc + (typeof s.valid === 'number' ? s.valid : 0), 0);
            const totalMailLocked = mine.reduce((acc, s) => acc + (typeof s.mailLocked === 'number' ? s.mailLocked : 0), 0);
            return sendJson(res, 200, {
                submissions: mine,
                stats: { totalFiles: mine.length, totalValid, totalMailLocked }
            });
        }

        if (pathname === '/api/submissions' && method === 'POST') {
            const db = await loadKvDb();
            const auth = getUserSession(db, token);
            if (!auth) {
                return sendJson(res, 401, { ok: false, error: 'يرجى تسجيل الدخول أولاً.' });
            }

            const cash = sanitizeText(body.cash, { maxLen: 64 });
            const tool = sanitizeText(body.tool, { maxLen: 100 });
            const fileName = sanitizeTxtFileName(body.fileName);
            const fileSize = Number(body.fileSize) || 0;
            const notes = sanitizeText(body.notes || 'لا يوجد', { maxLen: 500, allowNewlines: true }) || 'لا يوجد';
            const timestampAr = sanitizeText(body.timestampAr, { maxLen: 120 }) || new Date().toLocaleString('ar-EG');

            if (!cash || !tool || !fileName) {
                return sendJson(res, 400, { ok: false, error: 'بيانات التسليم غير مكتملة.' });
            }

            const parseOptionalCount = (raw) => {
                if (raw === null || raw === undefined) return { ok: true, value: null };
                const trimmed = String(raw).trim();
                if (trimmed === '') return { ok: true, value: null };
                if (!/^\d{1,7}$/.test(trimmed)) return { ok: false, value: null };
                return { ok: true, value: parseInt(trimmed, 10) };
            };
            const parsedValid = parseOptionalCount(body.valid);
            const parsedMailLocked = parseOptionalCount(body.mailLocked);
            if (!parsedValid.ok || !parsedMailLocked.ok) {
                return sendJson(res, 400, { ok: false, error: 'قيم الفحص غير صالحة.' });
            }
            const valid = parsedValid.value;
            const mailLocked = parsedMailLocked.value;

            const rawContent = String(body.fileContent || '');
            const record = {
                id: genId(),
                userId: auth.user.id,
                username: auth.user.username,
                name: auth.user.name,
                cash,
                tool,
                valid,
                mailLocked,
                notes,
                fileName,
                fileSize,
                fileContent: rawContent.slice(0, MAX_STORED_TXT_CHARS),
                fileTruncated: Boolean(body.fileTruncated) || rawContent.length > MAX_STORED_TXT_CHARS,
                timestampAr,
                createdAt: new Date().toISOString()
            };
            db.submissions.unshift(record);
            await saveKvDb(db);
            return sendJson(res, 200, { ok: true, submission: record });
        }

        // --- User HWID Activation Requests ---
        if (pathname === '/api/hwid/request' && method === 'POST') {
            const db = await loadKvDb();
            const auth = getUserSession(db, token);
            if (!auth) {
                return sendJson(res, 401, { ok: false, error: 'يرجى تسجيل الدخول أولاً.' });
            }

            const hwid = sanitizeText(body.hwid, { maxLen: 200 });
            const tool = sanitizeText(body.tool, { maxLen: 80 });
            if (hwid.length < 4 || hwid.length > 200) {
                return sendJson(res, 400, { ok: false, error: 'يرجى إدخال كود HWID صحيح.' });
            }
            if (tool.length < 1 || tool.length > 80) {
                return sendJson(res, 400, { ok: false, error: 'يرجى إدخال اسم التول.' });
            }

            const existing = db.hwids.find(h =>
                h.hwid.toLowerCase() === hwid.toLowerCase() &&
                String(h.tool || '').toLowerCase() === tool.toLowerCase()
            );
            if (existing) {
                return sendJson(res, 200, { ok: true, duplicate: true, record: existing });
            }

            const record = {
                id: genId(),
                userId: auth.user.id,
                userName: auth.user.name,
                username: auth.user.username,
                hwid,
                tool,
                status: 'pending',
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            };
            db.hwids.unshift(record);
            await saveKvDb(db);
            return sendJson(res, 200, { ok: true, duplicate: false, record });
        }

        if (pathname === '/api/hwid/mine' && method === 'GET') {
            const db = await loadKvDb();
            const auth = getUserSession(db, token);
            if (!auth) {
                return sendJson(res, 401, { ok: false, error: 'غير مسجل الدخول.' });
            }
            return sendJson(res, 200, { hwids: db.hwids.filter(h => h.userId === auth.user.id) });
        }

        // --- Vortex Keys ---
        if (pathname === '/api/vortex/status' && method === 'GET') {
            const db = await loadKvDb();
            const auth = getUserSession(db, token);
            if (!auth) {
                return sendJson(res, 401, { ok: false, error: 'يرجى تسجيل الدخول أولاً.' });
            }
            const availableCount = db.vortexKeys.filter(k => k.status === 'available').length;
            const myKeys = db.vortexKeys
                .filter(k => k.claimedByUserId === auth.user.id)
                .sort((a, b) => String(b.claimedAt || '').localeCompare(String(a.claimedAt || '')));
            return sendJson(res, 200, { availableCount, myKeys });
        }

        if (pathname === '/api/vortex/claim' && method === 'POST') {
            const db = await loadKvDb();
            const auth = getUserSession(db, token);
            if (!auth) {
                return sendJson(res, 401, { ok: false, error: 'يرجى تسجيل الدخول أولاً.' });
            }
            const nextKey = db.vortexKeys.find(k => k.status === 'available');
            if (!nextKey) {
                return sendJson(res, 409, { ok: false, error: 'غير متوفر الآن' });
            }
            nextKey.status = 'claimed';
            nextKey.claimedByUserId = auth.user.id;
            nextKey.claimedByName = auth.user.name;
            nextKey.claimedByUsername = auth.user.username;
            nextKey.claimedAt = new Date().toISOString();
            const availableCount = db.vortexKeys.filter(k => k.status === 'available').length;
            await saveKvDb(db);
            return sendJson(res, 200, { ok: true, key: nextKey, availableCount });
        }

        return sendJson(res, 404, { ok: false, error: 'المسار غير موجود.' });
    } catch (err) {
        return sendJson(res, err.status || 500, { ok: false, error: err.message || 'Server error.' });
    }
};
