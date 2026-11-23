// Helper hashing password (scrypt), token sesi (HMAC), dan sanitasi data santri.
const crypto = require('crypto');

function isHashed(val) {
    return typeof val === 'string' && val.startsWith('scrypt$');
}

function hashPassword(plain) {
    const raw = String(plain || '123456');
    if (isHashed(raw)) return raw;
    const salt = crypto.randomBytes(16).toString('hex');
    const derived = crypto.scryptSync(raw, salt, 64).toString('hex');
    return `scrypt$${salt}$${derived}`;
}

function verifyPassword(plain, stored) {
    const candidate = String(plain || '');
    if (!stored) return candidate === '123456';
    if (isHashed(stored)) {
        const parts = stored.split('$');
        if (parts.length !== 3) return false;
        const [, salt, expectedHex] = parts;
        const derivedBuf = crypto.scryptSync(candidate, salt, 64);
        const expectedBuf = Buffer.from(expectedHex, 'hex');
        if (derivedBuf.length !== expectedBuf.length) return false;
        return crypto.timingSafeEqual(derivedBuf, expectedBuf);
    }
    return candidate === String(stored);
}

function getTokenSecret() {
    const seed = process.env.AUTH_SECRET || process.env.APP_API_KEY || process.env.DATABASE_URL || process.env.POSTGRES_URL || 'jii-fallback-secret';
    return crypto.createHash('sha256').update(String(seed)).digest();
}

function createSessionToken(user) {
    const payload = {
        nis: String(user.nis || ''),
        role: String(user.role || 'santri'),
        exp: Date.now() + 7 * 24 * 60 * 60 * 1000
    };
    const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const sig = crypto.createHmac('sha256', getTokenSecret()).update(encoded).digest('base64url');
    return `${encoded}.${sig}`;
}

function verifySessionToken(req) {
    const authHeader = (req && req.headers && (req.headers.authorization || req.headers.Authorization)) || '';
    let token = '';
    if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
        token = authHeader.slice(7).trim();
    } else if (req && req.headers && req.headers['x-session-token']) {
        token = String(req.headers['x-session-token']).trim();
    }
    if (!token || !token.includes('.')) return null;

    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [encoded, sig] = parts;
    const expectedSig = crypto.createHmac('sha256', getTokenSecret()).update(encoded).digest('base64url');

    const sigBuf = Buffer.from(sig, 'utf8');
    const expBuf = Buffer.from(expectedSig, 'utf8');
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return null;

    try {
        const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
        if (!payload || !payload.nis || typeof payload.exp !== 'number' || payload.exp < Date.now()) return null;
        return payload;
    } catch (e) {
        return null;
    }
}

function sanitizeSantriForClient(santri) {
    if (!santri || typeof santri !== 'object') return santri;
    const copy = Object.assign({}, santri);
    copy.password = '';
    return copy;
}

module.exports = { isHashed, hashPassword, verifyPassword, createSessionToken, verifySessionToken, sanitizeSantriForClient };
