// Fungsi Vercel: sinkronisasi data ke database Neon (PostgreSQL).
// Variabel lingkungan (diisi di Vercel > Settings > Environment Variables):
//   DATABASE_URL = connection string dari Neon (wajib)
//   APP_API_KEY  = kunci bebas buatanmu (opsional, harus sama dengan SYNC_KEY di index.html)
const { DB_URL, getPool, ensureTables } = require('./_db');
const { hashPassword, sanitizeSantriForClient } = require('./_auth');

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
            if (size > 4 * 1024 * 1024) { reject(new Error('too large')); return; }
            chunks.push(c);
        });
        req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (e) { reject(e); } });
        req.on('error', reject);
    });
}

module.exports = async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-app-key');
    res.setHeader('Access-Control-Max-Age', '86400');

    if (req.method === 'OPTIONS') { res.statusCode = 204; return res.end(); }
    if (!DB_URL) return sendJson(res, 503, { error: 'DATABASE_URL belum diisi di Vercel' });
    if (API_KEY && req.headers['x-app-key'] !== API_KEY) return sendJson(res, 401, { error: 'Kunci aplikasi salah' });

    try {
        await ensureTables();

        if (req.method === 'GET') {
            const r = await getPool().query("SELECT data, version FROM app_state WHERE id = 'main'");
            if (r.rows.length === 0) return sendJson(res, 200, { empty: true });
            const safeList = Array.isArray(r.rows[0].data) ? r.rows[0].data.map(sanitizeSantriForClient) : [];
            return sendJson(res, 200, { data: safeList, version: Number(r.rows[0].version) });
        }

        if (req.method === 'PUT') {
            let body;
            try { body = await readJson(req); }
            catch (e) { return sendJson(res, 400, { error: 'Data tidak valid' }); }

            const { expectedVersion, data } = body || {};
            if (!Array.isArray(data)) return sendJson(res, 400, { error: 'data harus berupa array' });

            // Pertahankan hash password yang sudah ada di DB jika client mengirim password kosong
            const existingMap = new Map();
            const cur = await getPool().query("SELECT data FROM app_state WHERE id = 'main'");
            if (cur.rows.length > 0 && Array.isArray(cur.rows[0].data)) {
                cur.rows[0].data.forEach(item => {
                    if (item && item.nis && item.password) {
                        existingMap.set(String(item.nis), item.password);
                    }
                });
            }

            const securedData = data.map(item => {
                if (!item || typeof item !== 'object') return item;
                const copy = Object.assign({}, item);
                const rawPwd = String(copy.password || '').trim();
                if (rawPwd) {
                    copy.password = hashPassword(rawPwd);
                } else {
                    const prev = existingMap.get(String(copy.nis || ''));
                    copy.password = prev ? hashPassword(prev) : hashPassword('123456');
                }
                return copy;
            });

            const json = JSON.stringify(securedData);

            let r;
            if (expectedVersion === null || expectedVersion === undefined) {
                r = await getPool().query(
                    "INSERT INTO app_state (id, data, version) VALUES ('main', $1::jsonb, 1) ON CONFLICT (id) DO NOTHING RETURNING version",
                    [json]
                );
            } else {
                r = await getPool().query(
                    "UPDATE app_state SET data = $1::jsonb, version = version + 1 WHERE id = 'main' AND version = $2 RETURNING version",
                    [json, Number(expectedVersion)]
                );
            }
            if (r.rows.length === 0) return sendJson(res, 409, { error: 'Versi berubah, ulangi' });
            return sendJson(res, 200, { version: Number(r.rows[0].version) });
        }

        return sendJson(res, 405, { error: 'Metode tidak didukung' });
    } catch (err) {
        console.error(err);
        return sendJson(res, 500, { error: 'Kesalahan server' });
    }
};
