const {
    sendJson,
    getClientIp,
    verifyAdminRequest,
    createApiError,
    readRawBody,
    readJsonBody,
    sanitizeText,
    escapeTelegramHtml
} = require('./_auth');

const MAX_BODY_BYTES = 4718592; // 4.5 MiB Vercel Serverless payload ceiling
const MAX_TXT_BYTES = 4 * 1024 * 1024;
const MAX_IMG_BYTES = 4 * 1024 * 1024;
const MAX_MULTIPART_PARTS = 20;
const RATE_WINDOW_MS = 5 * 60 * 1000;
const RATE_MAX_REQUESTS = 12;

const submitRateStore = globalThis.__hTokenSubmitRate || (globalThis.__hTokenSubmitRate = new Map());

function checkSubmitRateLimit(ip, now) {
    if (submitRateStore.size > 300) {
        for (const [k, stamps] of submitRateStore.entries()) {
            const recent = Array.isArray(stamps) ? stamps.filter(ts => now - ts < RATE_WINDOW_MS) : [];
            if (recent.length === 0) submitRateStore.delete(k);
            else submitRateStore.set(k, recent);
        }
    }
    const existing = (submitRateStore.get(ip) || []).filter(ts => now - ts < RATE_WINDOW_MS);
    if (existing.length >= RATE_MAX_REQUESTS) {
        const oldest = existing[0];
        const retryAfterSeconds = Math.max(1, Math.ceil((oldest + RATE_WINDOW_MS - now) / 1000));
        return { allowed: false, retryAfterSeconds };
    }
    existing.push(now);
    submitRateStore.set(ip, existing);
    return { allowed: true, retryAfterSeconds: 0 };
}

function sanitizeFileName(rawName, requiredExt) {
    const base = String(rawName || '')
        .split(/[\\/]/)
        .pop()
        .replace(/[\u0000-\u001F\u007F<>:"|?*]/g, '')
        .replace(/\.\.+/g, '.')
        .trim();

    if (requiredExt === '.txt') {
        if (!/\.txt$/i.test(base)) return '';
        const stem = base.slice(0, -4).replace(/^\.+/, '').slice(0, 100) || 'report';
        return `${stem}.txt`;
    }
    const clean = base.replace(/^\.+/, '').slice(0, 100);
    return clean || 'check.png';
}

function detectImageMime(buf) {
    if (!Buffer.isBuffer(buf) || buf.length < 4) return '';
    if (buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47 &&
        buf[4] === 0x0d && buf[5] === 0x0a && buf[6] === 0x1a && buf[7] === 0x0a) {
        return 'image/png';
    }
    if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
        return 'image/jpeg';
    }
    if (buf.slice(0, 4).toString('ascii') === 'GIF8') {
        return 'image/gif';
    }
    if (buf.length >= 12 && buf.slice(0, 4).toString('ascii') === 'RIFF' && buf.slice(8, 12).toString('ascii') === 'WEBP') {
        return 'image/webp';
    }
    if (buf[0] === 0x42 && buf[1] === 0x4d) {
        return 'image/bmp';
    }
    return '';
}

function parseMultipartFormData(rawBuf, contentType) {
    const match = String(contentType || '').match(/boundary=(?:"([^"]+)"|([^;\s,]+))/i);
    if (!match) {
        throw createApiError(400, 'Missing multipart boundary.');
    }
    const boundary = (match[1] || match[2] || '').trim();
    if (!boundary || boundary.length > 200) {
        throw createApiError(400, 'Invalid multipart boundary.');
    }

    const delim = Buffer.from(`--${boundary}`, 'latin1');
    const fields = Object.create(null);
    const files = Object.create(null);

    let pos = rawBuf.indexOf(delim, 0);
    let partsCount = 0;

    while (pos !== -1) {
        let start = pos + delim.length;
        if (start + 2 <= rawBuf.length && rawBuf[start] === 0x2d && rawBuf[start + 1] === 0x2d) {
            break;
        }
        if (start + 2 <= rawBuf.length && rawBuf[start] === 0x0d && rawBuf[start + 1] === 0x0a) {
            start += 2;
        } else if (start + 1 <= rawBuf.length && rawBuf[start] === 0x0a) {
            start += 1;
        }

        const nextPos = rawBuf.indexOf(delim, start);
        if (nextPos === -1) break;

        partsCount++;
        if (partsCount > MAX_MULTIPART_PARTS) {
            throw createApiError(400, 'Too many multipart fields.');
        }

        let partEnd = nextPos;
        if (partEnd >= start + 2 && rawBuf[partEnd - 2] === 0x0d && rawBuf[partEnd - 1] === 0x0a) {
            partEnd -= 2;
        } else if (partEnd >= start + 1 && rawBuf[partEnd - 1] === 0x0a) {
            partEnd -= 1;
        }

        const partBuf = rawBuf.slice(start, partEnd);
        let sepLen = 4;
        let headerEnd = partBuf.indexOf(Buffer.from('\r\n\r\n', 'latin1'));
        if (headerEnd === -1) {
            headerEnd = partBuf.indexOf(Buffer.from('\n\n', 'latin1'));
            sepLen = 2;
        }
        if (headerEnd === -1) {
            pos = nextPos;
            continue;
        }

        const headerText = partBuf.slice(0, headerEnd).toString('utf8').replace(/\r?\n[ \t]+/g, ' ');
        const bodyBuf = partBuf.slice(headerEnd + sepLen);

        let dispLine = '';
        let partContentType = 'application/octet-stream';
        for (const line of headerText.split(/\r?\n/)) {
            const colonIdx = line.indexOf(':');
            if (colonIdx <= 0) continue;
            const headerName = line.slice(0, colonIdx).trim().toLowerCase();
            if (headerName === 'content-disposition') dispLine = line;
            else if (headerName === 'content-type') partContentType = line.slice(colonIdx + 1).trim();
        }

        const nameQuoted = dispLine.match(/;\s*name\s*=\s*"((?:\\.|[^"])*)"/i) || dispLine.match(/\bname\s*=\s*"((?:\\.|[^"])*)"/i);
        const nameBare = !nameQuoted ? dispLine.match(/;\s*name\s*=\s*([^;\s]+)/i) : null;
        const fieldName = nameQuoted
            ? nameQuoted[1].replace(/\\(.)/g, '$1')
            : (nameBare ? nameBare[1] : '');

        if (!fieldName || fieldName === '__proto__' || fieldName === 'constructor' || fieldName === 'prototype') {
            pos = nextPos;
            continue;
        }

        const fileExtMatch = dispLine.match(/;\s*filename\*\s*=\s*(?:"(?:[^']*'[^']*')?([^"\r\n]+)"|(?:[^']*'[^']*')?([^;\s\r\n]+))/i);
        const fileQuotedMatch = dispLine.match(/;\s*filename\s*=\s*"((?:\\.|[^"])*)"/i) || dispLine.match(/\bfilename\s*=\s*"((?:\\.|[^"])*)"/i);
        const fileBareMatch = !fileExtMatch && !fileQuotedMatch ? dispLine.match(/;\s*filename\s*=\s*([^;\r\n]+)/i) : null;

        if (fileExtMatch || fileQuotedMatch || fileBareMatch) {
            let decodedName = '';
            if (fileExtMatch) {
                const rawExt = String(fileExtMatch[1] || fileExtMatch[2] || '').trim();
                try { decodedName = decodeURIComponent(rawExt); } catch { decodedName = rawExt; }
            } else if (fileQuotedMatch) {
                decodedName = fileQuotedMatch[1].replace(/\\(.)/g, '$1');
            } else if (fileBareMatch) {
                decodedName = fileBareMatch[1].trim();
            }
            files[fieldName] = {
                filename: decodedName,
                contentType: partContentType,
                buffer: bodyBuf
            };
        } else {
            fields[fieldName] = bodyBuf.toString('utf8');
        }

        pos = nextPos;
    }

    return { fields, files };
}

async function callTelegramEndpoint(botToken, endpoint, formData) {
    const res = await fetch(`https://api.telegram.org/bot${botToken}/${endpoint}`, {
        method: 'POST',
        body: formData
    });
    const data = await res.json().catch(() => ({ ok: false, description: `HTTP ${res.status}` }));
    return { ok: Boolean(res.ok && data && data.ok), status: res.status, data };
}

async function handler(req, res) {
    const method = String(req.method || 'GET').toUpperCase();
    if (method !== 'POST') {
        return sendJson(res, 405, { ok: false, error: 'Method Not Allowed.' }, { Allow: 'POST' });
    }

    const botToken = String(process.env.BOT_TOKEN || '').trim();
    const chatId = String(process.env.CHAT_ID || '').trim();
    if (!botToken || !chatId) {
        return sendJson(res, 500, { ok: false, error: 'Telegram delivery configuration is missing on the server.' });
    }

    const clientIp = getClientIp(req);
    const rate = checkSubmitRateLimit(clientIp, Date.now());
    if (!rate.allowed) {
        return sendJson(res, 429, {
            ok: false,
            error: 'Too many submissions. Please wait a few minutes and try again.',
            retryAfterSeconds: rate.retryAfterSeconds
        }, {
            'Retry-After': String(rate.retryAfterSeconds)
        });
    }

    const rawContentType = String((req.headers && (req.headers['content-type'] || req.headers['Content-Type'])) || '');
    const contentTypeLower = rawContentType.toLowerCase();
    let fields = Object.create(null);
    let files = Object.create(null);

    try {
        if (contentTypeLower.includes('multipart/form-data')) {
            const rawBuf = await readRawBody(req, MAX_BODY_BYTES);
            const parsed = parseMultipartFormData(rawBuf, rawContentType);
            fields = parsed.fields;
            files = parsed.files;
        } else {
            const body = await readJsonBody(req, MAX_BODY_BYTES);
            if (body.action === 'test') {
                const adminAuth = verifyAdminRequest(req);
                if (!adminAuth.ok) {
                    return sendJson(res, 401, { ok: false, error: 'Admin authentication is required.' });
                }
                const testFd = new FormData();
                testFd.append('chat_id', chatId);
                testFd.append('document', new Blob([Buffer.from('تقرير تجريبي للتأكد من عمل البوت بنجاح.', 'utf8')], { type: 'text/plain; charset=utf-8' }), 'test_report.txt');
                testFd.append('caption', 'اختبار اتصال البوت بنجاح من لوحة الأدمن.');

                const testRes = await callTelegramEndpoint(botToken, 'sendDocument', testFd);
                if (!testRes.ok) {
                    console.error('Telegram testDocument failed:', testRes.status, testRes.data && testRes.data.description);
                    return sendJson(res, 502, { ok: false, error: 'Telegram rejected the test message.' });
                }
                return sendJson(res, 200, {
                    ok: true,
                    tested: true,
                    messageId: testRes.data && testRes.data.result ? testRes.data.result.message_id : null
                });
            }

            fields = body;
            if (typeof body.fileContent === 'string' || typeof body.fileName === 'string') {
                files.document = {
                    filename: String(body.fileName || 'report.txt'),
                    contentType: 'text/plain',
                    buffer: Buffer.from(String(body.fileContent || ''), 'utf8')
                };
            }
        }
    } catch (err) {
        return sendJson(res, err.status || 400, { ok: false, error: err.message || 'Invalid request payload.' });
    }

    const name = sanitizeText(fields.name || fields.username, { maxLen: 80 });
    const cash = sanitizeText(fields.cash, { maxLen: 64 });
    const tool = sanitizeText(fields.tool, { maxLen: 100 });
    const notes = sanitizeText(fields.notes || 'لا يوجد', { maxLen: 500, allowNewlines: true }) || 'لا يوجد';
    const validRaw = fields.valid !== undefined && fields.valid !== null
        ? String(fields.valid).trim()
        : (fields.validCount !== undefined && fields.validCount !== null ? String(fields.validCount).trim() : '');
    const mailLockedRaw = fields.mailLocked !== undefined && fields.mailLocked !== null
        ? String(fields.mailLocked).trim()
        : (fields.mailLockedCount !== undefined && fields.mailLockedCount !== null ? String(fields.mailLockedCount).trim() : '');
    const totalTokensRaw = fields.totalTokens !== undefined && fields.totalTokens !== null
        ? String(fields.totalTokens).trim()
        : (fields.totalTokensCount !== undefined && fields.totalTokensCount !== null ? String(fields.totalTokensCount).trim() : '');

    if (name.length < 2 || cash.length < 2 || tool.length < 1) {
        return sendJson(res, 400, { ok: false, error: 'Missing required report fields (name, cash, tool).' });
    }
    if ((validRaw !== '' && !/^\d{1,9}$/.test(validRaw)) ||
        (mailLockedRaw !== '' && !/^\d{1,9}$/.test(mailLockedRaw)) ||
        (totalTokensRaw !== '' && !/^\d{1,9}$/.test(totalTokensRaw))) {
        return sendJson(res, 400, { ok: false, error: 'Valid, Locked Mail, and Total Tokens counts must be non-negative integers.' });
    }

    const validCount = validRaw !== '' ? parseInt(validRaw, 10) : null;
    const mailLockedCount = mailLockedRaw !== '' ? parseInt(mailLockedRaw, 10) : null;
    const totalTokensCount = totalTokensRaw !== '' ? parseInt(totalTokensRaw, 10) : null;
    const validDisplay = validCount === null ? '-' : String(validCount);
    const mailLockedDisplay = mailLockedCount === null ? '-' : String(mailLockedCount);
    const totalTokensDisplay = totalTokensCount === null ? '-' : String(totalTokensCount);

    const docFile = files.document;
    if (!docFile || !Buffer.isBuffer(docFile.buffer)) {
        return sendJson(res, 400, { ok: false, error: 'A .txt report file is required.' });
    }
    const safeDocName = sanitizeFileName(docFile.filename, '.txt');
    if (!safeDocName) {
        return sendJson(res, 400, { ok: false, error: 'Only .txt report files are accepted.' });
    }
    if (docFile.buffer.length < 1 || docFile.buffer.length > MAX_TXT_BYTES) {
        return sendJson(res, 400, { ok: false, error: 'The .txt file must be non-empty and at most 4 MB.' });
    }
    if (docFile.buffer.includes(0)) {
        return sendJson(res, 400, { ok: false, error: 'Invalid binary content inside .txt file.' });
    }

    const photoFile = files.photo || null;
    let detectedPhotoMime = '';
    let safePhotoName = '';
    if (photoFile && Buffer.isBuffer(photoFile.buffer) && photoFile.buffer.length > 0) {
        if (photoFile.buffer.length > MAX_IMG_BYTES) {
            return sendJson(res, 400, { ok: false, error: 'Screenshot image exceeds maximum allowed size.' });
        }
        detectedPhotoMime = detectImageMime(photoFile.buffer);
        if (!detectedPhotoMime) {
            return sendJson(res, 400, { ok: false, error: 'Invalid check screenshot image format.' });
        }
        safePhotoName = sanitizeFileName(photoFile.filename, '');
    }

    const timestampAr = sanitizeText(fields.timestampAr, { maxLen: 120 }) || new Date().toLocaleString('ar-EG', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });

    const statsBlock = `\n<b>Valid /</b>\n<code>${escapeTelegramHtml(validDisplay)}</code>\n\n<b>Locked Mail /</b>\n<code>${escapeTelegramHtml(mailLockedDisplay)}</code>\n\n<b>Total Tokens /</b>\n<code>${escapeTelegramHtml(totalTokensDisplay)}</code>\n`;
    const caption =
        `<b>تقرير عمل يومي جديد</b>
────────────────────

<b>الاسم /</b>
${escapeTelegramHtml(name)}

<b>رقم الكاش /</b>
<code>${escapeTelegramHtml(cash)}</code>

<b>اسم التول /</b>
${escapeTelegramHtml(tool)}
${statsBlock}
<b>التاريخ والوقت /</b>
${escapeTelegramHtml(timestampAr)}

<b>اسم الملف /</b>
<code>${escapeTelegramHtml(safeDocName)}</code>

<b>ملاحظات /</b>
${escapeTelegramHtml(notes)}`;

    try {
        const docFd = new FormData();
        docFd.append('chat_id', chatId);
        docFd.append('document', new Blob([docFile.buffer], { type: 'text/plain; charset=utf-8' }), safeDocName);
        docFd.append('parse_mode', 'HTML');
        docFd.append('caption', caption);

        const docRes = await callTelegramEndpoint(botToken, 'sendDocument', docFd);
        if (!docRes.ok) {
            console.error('Telegram sendDocument failed:', docRes.status, docRes.data && docRes.data.description);
            return sendJson(res, 502, { ok: false, error: 'Failed to deliver report to Telegram.' });
        }

        const docMessageId = docRes.data && docRes.data.result ? docRes.data.result.message_id : null;

        if (photoFile && detectedPhotoMime) {
            const imgCaption = `<b>صورة الفحص</b> — ${escapeTelegramHtml(name)} (${escapeTelegramHtml(tool)})\nValid: <code>${escapeTelegramHtml(validDisplay)}</code> | Locked Mail: <code>${escapeTelegramHtml(mailLockedDisplay)}</code> | Total Tokens: <code>${escapeTelegramHtml(totalTokensDisplay)}</code>`;
            const photoFd = new FormData();
            photoFd.append('chat_id', chatId);
            photoFd.append('photo', new Blob([photoFile.buffer], { type: detectedPhotoMime }), safePhotoName);
            photoFd.append('parse_mode', 'HTML');
            photoFd.append('caption', imgCaption);
            if (docMessageId) {
                photoFd.append('reply_to_message_id', String(docMessageId));
            }

            const photoRes = await callTelegramEndpoint(botToken, 'sendPhoto', photoFd);
            if (!photoRes.ok) {
                const imgDocFd = new FormData();
                imgDocFd.append('chat_id', chatId);
                imgDocFd.append('document', new Blob([photoFile.buffer], { type: detectedPhotoMime }), safePhotoName);
                imgDocFd.append('parse_mode', 'HTML');
                imgDocFd.append('caption', imgCaption);
                if (docMessageId) {
                    imgDocFd.append('reply_to_message_id', String(docMessageId));
                }

                const fallbackRes = await callTelegramEndpoint(botToken, 'sendDocument', imgDocFd);
                if (!fallbackRes.ok) {
                    console.error('Telegram screenshot delivery failed:', fallbackRes.status, fallbackRes.data && fallbackRes.data.description);
                    return sendJson(res, 502, { ok: false, error: 'Report sent, but screenshot upload failed.' });
                }
            }
        }

        return sendJson(res, 200, {
            ok: true,
            messageId: docMessageId,
            fileName: safeDocName,
            hasPhoto: Boolean(photoFile && detectedPhotoMime),
            timestampAr
        });
    } catch (err) {
        console.error('Telegram upstream request error:', err && err.message);
        return sendJson(res, 502, { ok: false, error: 'Upstream Telegram delivery failed.' });
    }
}

module.exports = handler;
module.exports.config = {
    api: {
        bodyParser: false
    }
};
