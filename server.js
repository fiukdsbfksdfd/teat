/**
 * Key Auth Server
 *
 * - Custom key format: <GROUP>-<RANDOM>-<EXP>-<SIG>   (SIG = HMAC-SHA256)
 * - AES-256-GCM helpers for encrypting sensitive payloads
 * - HWID binding and reset
 * - IP checks (per-key allowlist)
 * - Optional cert fingerprint check (header or mTLS)
 * - Admin dashboard routes locked to ADMIN_IP and ADMIN_API_KEY
 *
 * Environment variables (example):
 *   PORT=3000
 *   DB_PATH=./data/keys.db
 *   AES_KEY=base64:...      (32 bytes raw -> base64)
 *   HMAC_KEY=base64:...     (for signing keys)
 *   ADMIN_IP=1.2.3.4
 *   ADMIN_API_KEY=some-secret
 *   CERT_FINGERPRINT_HEADER=x-client-cert-fp   (optional)
 *
 * NOTE: keep AES_KEY and HMAC_KEY secret (Render secret env vars).
 */

const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || './data/keys.db';
const AES_KEY_B64 = process.env.AES_KEY;    // expected base64 of 32 bytes
const HMAC_KEY_B64 = process.env.HMAC_KEY;  // expected base64 key for signing/verifying
const ADMIN_IP = process.env.ADMIN_IP || null;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || null;
const CERT_FP_HEADER = process.env.CERT_FINGERPRINT_HEADER || 'x-client-cert-fp';

if (!AES_KEY_B64 || !HMAC_KEY_B64) {
  console.error('ERROR: AES_KEY and HMAC_KEY environment variables are required (base64).');
  process.exit(1);
}

const AES_KEY = Buffer.from(AES_KEY_B64.replace(/^base64:/,''), 'base64');
const HMAC_KEY = Buffer.from(HMAC_KEY_B64.replace(/^base64:/,''), 'base64');

if (AES_KEY.length !== 32) {
  console.error('ERROR: AES_KEY must be 32 bytes (base64-encoded).');
  process.exit(1);
}

const app = express();
app.use(helmet());
app.use(bodyParser.json({ limit: '200kb' }));
app.use(cors());
app.use(morgan('combined'));

// basic rate limiter for validation endpoint
const limiter = rateLimit({
  windowMs: 10 * 1000, // 10 seconds
  max: 50,
  message: { error: 'Too many requests, slow down.' }
});

const db = new Database(DB_PATH);

// Initialize DB
db.exec(`
CREATE TABLE IF NOT EXISTS keys (
  id TEXT PRIMARY KEY,
  key_text TEXT UNIQUE,
  group_name TEXT,
  created_at INTEGER,
  expires_at INTEGER,
  time_length_seconds INTEGER,
  bind_on_first_use INTEGER DEFAULT 1,
  bound_hwid TEXT,
  allowed_ips TEXT,         -- JSON array
  allowed_cert_fps TEXT,    -- JSON array
  extra JSON
);

CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key_id TEXT,
  key_text TEXT,
  event TEXT,
  hwid TEXT,
  ip TEXT,
  cert_fp TEXT,
  created_at INTEGER
);
`);

// ---------- Utilities ----------
function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function hmacSign(data) {
  return crypto.createHmac('sha256', HMAC_KEY).update(data).digest('hex');
}

function aesEncrypt(plain) {
  // AES-256-GCM
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

function aesDecrypt(b64) {
  const data = Buffer.from(b64, 'base64');
  const iv = data.slice(0, 12);
  const tag = data.slice(12, 28);
  const encrypted = data.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', AES_KEY, iv);
  decipher.setAuthTag(tag);
  const out = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return JSON.parse(out.toString('utf8'));
}

function makeRandomSegment(len = 8) {
  return crypto.randomBytes(len).toString('hex').toUpperCase();
}

/**
 * Key format:
 *   <GROUP>-<RANDOM>-<EXP>-<SIG>
 * where
 *   GROUP = alphanumeric group slug
 *   RANDOM = random hex segment
 *   EXP = unix timestamp of expiry (seconds)
 *   SIG = HMAC-SHA256 of "<GROUP>-<RANDOM>-<EXP>"
 */
function generateKeyToken({ group='DEFAULT', lifetimeSeconds = 86400 * 30 }) {
  const random = makeRandomSegment(6);
  const exp = nowSeconds() + lifetimeSeconds;
  const payload = `${group}-${random}-${exp}`;
  const sig = hmacSign(payload);
  return `${group}-${random}-${exp}-${sig}`;
}

function parseKeyToken(token) {
  const parts = token.split('-');
  if (parts.length < 4) return null;
  // last part is sig, first is group, second random, third is exp (may contain extra dashes if random had dashes)
  const sig = parts[parts.length - 1];
  const exp = parts[parts.length - 2];
  const group = parts[0];
  const random = parts.slice(1, parts.length - 2).join('-');
  const payload = `${group}-${random}-${exp}`;
  const expected = hmacSign(payload);
  return {
    validSig: crypto.timingSafeEqual(Buffer.from(expected,'hex'), Buffer.from(sig,'hex')),
    group,
    random,
    exp: Number(exp),
    sig,
    rawPayload: payload
  };
}

function logEvent({ key_id=null, key_text=null, event, hwid=null, ip=null, cert_fp=null }) {
  const stmt = db.prepare(`INSERT INTO logs (key_id, key_text, event, hwid, ip, cert_fp, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`);
  stmt.run(key_id, key_text, event, hwid, ip, cert_fp, nowSeconds());
}

// ---------- Middlewares ----------
function adminGuard(req, res, next) {
  // IP lock
  const requesterIp = req.ip || req.connection.remoteAddress;
  if (ADMIN_IP && requesterIp !== ADMIN_IP && requesterIp !== `::ffff:${ADMIN_IP}`) {
    return res.status(401).json({ error: 'Admin IP not allowed' });
  }
  // API key
  const incoming = req.headers['x-admin-api-key'] || req.query.adminApiKey || req.body.adminApiKey;
  if (!ADMIN_API_KEY || incoming !== ADMIN_API_KEY) {
    return res.status(401).json({ error: 'Admin API key required' });
  }
  next();
}

// ---------- Public API ----------
/**
 * Validate a key
 * POST /validate
 * body: { key: string, hwid?: string, payload?: {...} }
 * headers used:
 *   CERT_FP_HEADER (optional) - fingerprint of client certificate if provided by proxy/mTLS
 */
app.post('/validate', limiter, (req, res) => {
  try {
    const { key: keyText, hwid } = req.body || {};
    const ip = req.ip || req.connection.remoteAddress;
    const certFp = req.headers[CERT_FP_HEADER] || null;

    if (!keyText) return res.status(400).json({ ok: false, error: 'key required' });

    const parsed = parseKeyToken(keyText);
    if (!parsed || !parsed.validSig) {
      return res.status(401).json({ ok: false, error: 'invalid signature or format' });
    }

    // quick expiry check from token
    if (parsed.exp && parsed.exp < nowSeconds()) {
      return res.status(403).json({ ok: false, error: 'key expired (token-level)' });
    }

    const row = db.prepare('SELECT * FROM keys WHERE key_text = ?').get(keyText);
    if (!row) {
      logEvent({ key_text: keyText, event: 'not_found', hwid, ip, cert_fp });
      return res.status(404).json({ ok: false, error: 'key not registered' });
    }

    // Check DB expiry
    if (row.expires_at && row.expires_at < nowSeconds()) {
      logEvent({ key_id: row.id, key_text: keyText, event: 'expired', hwid, ip, cert_fp });
      return res.status(403).json({ ok: false, error: 'key expired' });
    }

    // Allowed IPs check
    if (row.allowed_ips) {
      let allowedList;
      try { allowedList = JSON.parse(row.allowed_ips); } catch (e) { allowedList = []; }
      if (Array.isArray(allowedList) && allowedList.length > 0) {
        // if requester's ip not in allowed list -> fail
        // allow both IPv4 and mapped IPv6 ::ffff:a.b.c.d
        const normalized = ip;
        const allowedNormalized = allowedList.map(a => a.trim());
        if (!allowedNormalized.includes(normalized) && !allowedNormalized.includes(normalized.replace(/^::ffff:/, ''))) {
          logEvent({ key_id: row.id, key_text: keyText, event: 'ip_blocked', hwid, ip, cert_fp });
          return res.status(403).json({ ok: false, error: 'IP not allowed for this key' });
        }
      }
    }

    // Cert fingerprint checks (optional)
    if (row.allowed_cert_fps) {
      let allowedCerts;
      try { allowedCerts = JSON.parse(row.allowed_cert_fps); } catch (e) { allowedCerts = []; }
      if (Array.isArray(allowedCerts) && allowedCerts.length > 0) {
        if (!certFp || !allowedCerts.includes(certFp)) {
          logEvent({ key_id: row.id, key_text: keyText, event: 'cert_blocked', hwid, ip, cert_fp });
          return res.status(403).json({ ok: false, error: 'certificate fingerprint not allowed' });
        }
      }
    }

    // HWID handling
    if (row.bind_on_first_use) {
      if (!row.bound_hwid) {
        // bind to provided hwid
        if (!hwid) {
          logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_required_bind', hwid, ip, cert_fp });
          return res.status(400).json({ ok:false, error: 'hwid required to bind key' });
        }
        // store binding
        db.prepare('UPDATE keys SET bound_hwid = ? WHERE id = ?').run(hwid, row.id);
        logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_bound', hwid, ip, cert_fp });
      } else {
        // already bound: compare
        if (hwid && hwid !== row.bound_hwid) {
          logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_mismatch', hwid, ip, cert_fp });
          return res.status(403).json({ ok: false, error: 'hwid mismatch' });
        }
        if (!hwid) {
          logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_missing', hwid, ip, cert_fp });
          return res.status(400).json({ ok:false, error: 'hwid required' });
        }
      }
    } else {
      // not bind-on-first-use, but may have bound_hwid pre-set
      if (row.bound_hwid) {
        if (!hwid) {
          logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_missing', hwid, ip, cert_fp });
          return res.status(400).json({ ok:false, error: 'hwid required' });
        }
        if (hwid !== row.bound_hwid) {
          logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_mismatch', hwid, ip, cert_fp });
          return res.status(403).json({ ok: false, error: 'hwid mismatch' });
        }
      }
    }

    // Passed all checks
    logEvent({ key_id: row.id, key_text: keyText, event: 'validated', hwid, ip, cert_fp });

    // return encrypted payload with metadata (example)
    const payload = {
      id: row.id,
      group: row.group_name,
      expires_at: row.expires_at,
      server_time: nowSeconds()
    };
    const encrypted = aesEncrypt(payload);

    return res.json({ ok: true, message: 'valid', token: encrypted });
  } catch (err) {
    console.error('validate error', err);
    return res.status(500).json({ ok: false, error: 'server error' });
  }
});

// ---------- Admin Dashboard APIs (protected) ----------
/**
 * Add a key
 * POST /admin/key/add
 * body: {
 *   group: string,
 *   lifetimeSeconds: number,
 *   bindOnFirstUse: boolean,
 *   allowedIps: [ip],
 *   allowedCertFPs: [fp],
 *   extra: { ... }
 * }
 */
app.post('/admin/key/add', adminGuard, (req, res) => {
  try {
    const { group='DEFAULT', lifetimeSeconds = 86400 * 30, bindOnFirstUse = true, allowedIps = [], allowedCertFPs = [], extra = {} } = req.body || {};

    const keyText = generateKeyToken({ group, lifetimeSeconds });
    const id = uuidv4();
    const created = nowSeconds();
    const expires = created + Number(lifetimeSeconds || 0);

    db.prepare(`INSERT INTO keys (
      id, key_text, group_name, created_at, expires_at, time_length_seconds, bind_on_first_use, bound_hwid, allowed_ips, allowed_cert_fps, extra
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).
    run(id, keyText, group, created, expires, lifetimeSeconds, bindOnFirstUse ? 1 : 0, null, JSON.stringify(allowedIps || []), JSON.stringify(allowedCertFPs || []), JSON.stringify(extra || {}));

    logEvent({ key_id: id, key_text: keyText, event: 'created', hwid: null, ip: req.ip, cert_fp: req.headers[CERT_FP_HEADER] || null });

    return res.json({ ok: true, key: keyText, id, group, expires_at: expires });
  } catch (err) {
    console.error('add key error', err);
    return res.status(500).json({ ok:false, error:'server error' });
  }
});

/**
 * Remove a key
 * POST /admin/key/remove
 * body: { key: string } OR { id: string }
 */
app.post('/admin/key/remove', adminGuard, (req, res) => {
  const { key, id } = req.body || {};
  if (!key && !id) return res.status(400).json({ ok:false, error:'key or id required' });
  let row;
  if (id) row = db.prepare('SELECT * FROM keys WHERE id = ?').get(id);
  else row = db.prepare('SELECT * FROM keys WHERE key_text = ?').get(key);
  if (!row) return res.status(404).json({ ok:false, error:'not found' });
  db.prepare('DELETE FROM keys WHERE id = ?').run(row.id);
  logEvent({ key_id: row.id, key_text: row.key_text, event: 'deleted', hwid:null, ip: req.ip, cert_fp: req.headers[CERT_FP_HEADER] || null });
  return res.json({ ok:true, deleted: row.id });
});

/**
 * Reset/unbind HWID
 * POST /admin/key/reset-hwid
 * body: { key: string } OR { id: string }
 */
app.post('/admin/key/reset-hwid', adminGuard, (req, res) => {
  const { key, id } = req.body || {};
  if (!key && !id) return res.status(400).json({ ok:false, error:'key or id required' });
  let row;
  if (id) row = db.prepare('SELECT * FROM keys WHERE id = ?').get(id);
  else row = db.prepare('SELECT * FROM keys WHERE key_text = ?').get(key);
  if (!row) return res.status(404).json({ ok:false, error:'not found' });
  db.prepare('UPDATE keys SET bound_hwid = NULL WHERE id = ?').run(row.id);
  logEvent({ key_id: row.id, key_text: row.key_text, event: 'hwid_unbound', hwid:null, ip: req.ip, cert_fp: req.headers[CERT_FP_HEADER] || null });
  return res.json({ ok:true, id: row.id, message: 'hwid unbound' });
});

/**
 * List keys (paginated)
 * GET /admin/keys?limit=50&offset=0
 */
app.get('/admin/keys', adminGuard, (req, res) => {
  const limit = Math.min(200, Number(req.query.limit || 50));
  const offset = Number(req.query.offset || 0);
  const rows = db.prepare('SELECT id, key_text, group_name, created_at, expires_at, bind_on_first_use, bound_hwid FROM keys ORDER BY created_at DESC LIMIT ? OFFSET ?').all(limit, offset);
  return res.json({ ok:true, keys: rows });
});

/**
 * Get key details
 * GET /admin/key/:id
 */
app.get('/admin/key/:id', adminGuard, (req, res) => {
  const id = req.params.id;
  const row = db.prepare('SELECT * FROM keys WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ ok:false, error:'not found' });
  // parse extras
  try {
    row.allowed_ips = JSON.parse(row.allowed_ips || '[]');
    row.allowed_cert_fps = JSON.parse(row.allowed_cert_fps || '[]');
    row.extra = JSON.parse(row.extra || '{}');
  } catch (e) {}
  return res.json({ ok:true, key: row });
});

/**
 * Add or remove allowed IPs / cert fps
 * POST /admin/key/update
 * body: { id: string, allowedIps?: [], allowedCertFPs?: [], expiresAt?: unixSeconds }
 */
app.post('/admin/key/update', adminGuard, (req, res) => {
  const { id, allowedIps, allowedCertFPs, expiresAt, bindOnFirstUse } = req.body || {};
  if (!id) return res.status(400).json({ ok:false, error:'id required' });
  const row = db.prepare('SELECT * FROM keys WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ ok:false, error:'not found' });

  const stmt = db.prepare(`UPDATE keys SET allowed_ips = ?, allowed_cert_fps = ?, expires_at = ?, bind_on_first_use = ? WHERE id = ?`);
  stmt.run(
    allowedIps ? JSON.stringify(allowedIps) : row.allowed_ips,
    allowedCertFPs ? JSON.stringify(allowedCertFPs) : row.allowed_cert_fps,
    expiresAt ? Number(expiresAt) : row.expires_at,
    bindOnFirstUse === undefined ? row.bind_on_first_use : (bindOnFirstUse ? 1 : 0),
    id
  );
  logEvent({ key_id: id, key_text: row.key_text, event: 'updated', hwid:null, ip:req.ip, cert_fp: req.headers[CERT_FP_HEADER] || null });
  return res.json({ ok:true, id });
});

// ---------- Basic server health and admin info ----------
app.get('/', (req, res) => {
  res.send({ ok:true, server_time: nowSeconds(), env: process.env.NODE_ENV || 'production' });
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`Key auth server listening on port ${PORT}`);
  console.log(`DB: ${DB_PATH}`);
});
