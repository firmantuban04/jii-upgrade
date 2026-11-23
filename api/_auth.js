// Helper hashing password (scrypt) dan sanitasi data santri untuk API Vercel.
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

function sanitizeSantriForClient(santri) {
    if (!santri || typeof santri !== 'object') return santri;
    const copy = Object.assign({}, santri);
    copy.password = '';
    return copy;
}

module.exports = { isHashed, hashPassword, verifyPassword, sanitizeSantriForClient };
