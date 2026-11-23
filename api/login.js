// Fungsi Vercel: verifikasi login santri/pengurus di sisi server (password ter-hash).
const { DB_URL, getPool, ensureTables } = require('./_db');
const { verifyPassword, sanitizeSantriForClient } = require('./_auth');

const API_KEY = process.env.APP_API_KEY || '';

function sendJson(res, status, obj) {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-store');
    res.end(JSON.stringify(obj));
}

function readJson(req) {
    if (req.body !== undefined && req.body !== null) {
        if (typeof req.body === 'string') return Promise.resolve(JSON.parse(req.body));
        if (Buffer.isBuffer(req.body)) return Promise.resolve(JSON.parse(req.body.toString('utf8')));
        return Promise.resolve(req.body);
    }
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        req.on('data', c => {
            size += c.length;
            if (size > 1024 * 1024) { reject(new Error('too large')); return; }
            chunks.push(c);
        });
        req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (e) { reject(e); } });
        req.on('error', reject);
    });
}

module.exports = async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-app-key');
    res.setHeader('Access-Control-Max-Age', '86400');

    if (req.method === 'OPTIONS') { res.statusCode = 204; return res.end(); }
    if (req.method !== 'POST') return sendJson(res, 405, { error: 'Metode tidak didukung' });
    if (!DB_URL) return sendJson(res, 503, { error: 'DATABASE_URL belum diisi di Vercel' });
    if (API_KEY && req.headers['x-app-key'] !== API_KEY) return sendJson(res, 401, { error: 'Kunci aplikasi salah' });

    let body;
    try { body = await readJson(req); }
    catch (e) { return sendJson(res, 400, { error: 'Data login tidak valid' }); }

    const nis = String((body && body.nis) || '').trim();
    const password = String((body && body.password) || '').trim();
    if (!nis || !password) return sendJson(res, 400, { ok: false, error: 'NIS dan password wajib diisi' });

    try {
        await ensureTables();
        const r = await getPool().query("SELECT data FROM app_state WHERE id = 'main'");
        if (r.rows.length === 0 || !Array.isArray(r.rows[0].data) || r.rows[0].data.length === 0) {
            return sendJson(res, 200, { ok: false, empty: true });
        }

        const list = r.rows[0].data;
        const matched = list.find(s => String(s.nis || '').toUpperCase() === nis.toUpperCase());
        if (!matched) {
            return sendJson(res, 404, { ok: false, error: 'Akun dengan NIS / ID tersebut tidak ditemukan!' });
        }

        if (!verifyPassword(password, matched.password)) {
            return sendJson(res, 401, { ok: false, error: 'Password salah!' });
        }

        return sendJson(res, 200, { ok: true, user: sanitizeSantriForClient(matched) });
    } catch (err) {
        console.error(err);
        return sendJson(res, 500, { error: 'Kesalahan server' });
    }
};
