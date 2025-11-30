/**
 * Key Auth Server - FIXED VERSION
 *
 * - Custom key format: <GROUP>-<RANDOM>-<EXP>-<SIG>   (SIG = HMAC-SHA256)
 * - AES-256-GCM helpers for encrypting sensitive payloads
 * - HWID binding and reset
 * - IP checks (per-key allowlist)
 * - Optional cert fingerprint check (header or mTLS)
 * - Admin dashboard routes locked to ADMIN_IP and ADMIN_API_KEY
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
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || './data/keys.db';
const AES_KEY_B64 = process.env.AES_KEY;
const HMAC_KEY_B64 = process.env.HMAC_KEY;
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

// Rate limiters
const validateLimiter = rateLimit({
  windowMs: 10 * 1000,
  max: 50,
  message: { error: 'Too many requests, slow down.' }
});

const adminLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Too many admin requests, slow down.' }
});

// Ensure DB directory exists
const dir = path.dirname(DB_PATH);
if (!fs.existsSync(dir)) {
  fs.mkdirSync(dir, { recursive: true });
  console.log("Created missing DB directory:", dir);
}

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
  allowed_ips TEXT,
  allowed_cert_fps TEXT,
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

function normalizeIP(ip) {
  // Strip IPv6 prefix if present
  return ip.replace(/^::ffff:/i, '');
}

/**
 * Key format: <GROUP>-<RANDOM>-<EXP>-<SIG>
 */
function generateKeyToken({ group='DEFAULT', lifetimeSeconds = 86400 * 30 }) {
  const random = makeRandomSegment(6);
  const exp = nowSeconds() + lifetimeSeconds;
  const payload = `${group}-${random}-${exp}`;
  const sig = hmacSign(payload);
  return `${payload}-${sig}`;
}

function parseKeyToken(token) {
  try {
    if (!token || typeof token !== 'string') return null;
    
    const parts = token.split('-');
    if (parts.length < 4) return null;
    
    const sig = parts[parts.length - 1];
    const exp = parts[parts.length - 2];
    const group = parts[0];
    const random = parts.slice(1, parts.length - 2).join('-');
    
    // Validate expiry is a valid number
    const expNum = Number(exp);
    if (!Number.isInteger(expNum) || expNum < 0) return null;
    
    // Validate signature is valid hex
    if (!/^[0-9a-fA-F]+$/.test(sig)) return null;
    
    const payload = `${group}-${random}-${exp}`;
    const expected = hmacSign(payload);
    
    // FIXED: Proper signature comparison with same-length buffers
    let validSig = false;
    try {
      if (sig.length === expected.length && sig.length === 64) {
        const sigBuf = Buffer.from(sig, 'hex');
        const expBuf = Buffer.from(expected, 'hex');
        
        // Ensure both buffers are 32 bytes (SHA256 output)
        if (sigBuf.length === 32 && expBuf.length === 32) {
          validSig = crypto.timingSafeEqual(sigBuf, expBuf);
        }
      }
    } catch (e) {
      console.error('Signature comparison error:', e);
      validSig = false;
    }
    
    return {
      validSig,
      group,
      random,
      exp: expNum,
      sig,
      rawPayload: payload
    };
  } catch (err) {
    console.error('parseKeyToken error:', err);
    return null;
  }
}

function logEvent({ key_id=null, key_text=null, event, hwid=null, ip=null, cert_fp=null }) {
  try {
    const stmt = db.prepare(`INSERT INTO logs (key_id, key_text, event, hwid, ip, cert_fp, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`);
    stmt.run(key_id, key_text, event, hwid, ip, cert_fp, nowSeconds());
  } catch (err) {
    console.error('logEvent error:', err);
  }
}

// ---------- Middlewares ----------
function adminGuard(req, res, next) {
  const requesterIp = normalizeIP(req.ip || req.connection.remoteAddress);
  const normalizedAdminIp = ADMIN_IP ? normalizeIP(ADMIN_IP) : null;
  
  if (normalizedAdminIp && requesterIp !== normalizedAdminIp) {
    return res.status(401).json({ error: 'Admin IP not allowed' });
  }
  
  const incoming = req.headers['x-admin-api-key'] || req.query.adminApiKey || req.body?.adminApiKey;
  if (!ADMIN_API_KEY || incoming !== ADMIN_API_KEY) {
    return res.status(401).json({ error: 'Admin API key required' });
  }
  next();
}

// ---------- Public API ----------
app.post('/validate', validateLimiter, (req, res) => {
  try {
    const { key: keyText, hwid } = req.body || {};
    const ip = normalizeIP(req.ip || req.connection.remoteAddress);
    const certFp = req.headers[CERT_FP_HEADER] || null;

    console.log(`[VALIDATE] Key: ${keyText}, HWID: ${hwid}, IP: ${ip}`);

    if (!keyText) return res.status(400).json({ ok: false, error: 'key required' });

    const parsed = parseKeyToken(keyText);
    console.log('[VALIDATE] Parsed:', parsed);
    
    if (!parsed || !parsed.validSig) {
      logEvent({ key_text: keyText, event: 'invalid_format', hwid, ip, cert_fp });
      return res.status(401).json({ ok: false, error: 'invalid signature or format' });
    }

    // Token-level expiry check
    if (parsed.exp && parsed.exp < nowSeconds()) {
      logEvent({ key_text: keyText, event: 'expired_token', hwid, ip, cert_fp });
      return res.status(403).json({ ok: false, error: 'key expired (token-level)' });
    }

    const row = db.prepare('SELECT * FROM keys WHERE key_text = ?').get(keyText);
    if (!row) {
      logEvent({ key_text: keyText, event: 'not_found', hwid, ip, cert_fp });
      return res.status(404).json({ ok: false, error: 'key not registered' });
    }

    // DB expiry check
    if (row.expires_at && row.expires_at < nowSeconds()) {
      logEvent({ key_id: row.id, key_text: keyText, event: 'expired', hwid, ip, cert_fp });
      return res.status(403).json({ ok: false, error: 'key expired' });
    }

    // IP check
    if (row.allowed_ips) {
      let allowedList;
      try { 
        allowedList = JSON.parse(row.allowed_ips); 
      } catch (e) { 
        allowedList = []; 
      }
      
      if (Array.isArray(allowedList) && allowedList.length > 0) {
        const allowedNormalized = allowedList.map(a => normalizeIP(a.trim()));
        if (!allowedNormalized.includes(ip)) {
          logEvent({ key_id: row.id, key_text: keyText, event: 'ip_blocked', hwid, ip, cert_fp });
          return res.status(403).json({ ok: false, error: 'IP not allowed for this key' });
        }
      }
    }

    // Cert fingerprint check
    if (row.allowed_cert_fps) {
      let allowedCerts;
      try { 
        allowedCerts = JSON.parse(row.allowed_cert_fps); 
      } catch (e) { 
        allowedCerts = []; 
      }
      
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
        if (!hwid) {
          logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_required_bind', hwid, ip, cert_fp });
          return res.status(400).json({ ok:false, error: 'hwid required to bind key' });
        }
        db.prepare('UPDATE keys SET bound_hwid = ? WHERE id = ?').run(hwid, row.id);
        logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_bound', hwid, ip, cert_fp });
      } else {
        if (hwid && hwid !== row.bound_hwid) {
          logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_mismatch', hwid, ip, cert_fp });
          return res.status(403).json({ ok: false, error: 'hwid mismatch' });
        }
        if (!hwid) {
          logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_missing', hwid, ip, cert_fp });
          return res.status(400).json({ ok:false, error: 'hwid required' });
        }
      }
    } else if (row.bound_hwid) {
      if (!hwid) {
        logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_missing', hwid, ip, cert_fp });
        return res.status(400).json({ ok:false, error: 'hwid required' });
      }
      if (hwid !== row.bound_hwid) {
        logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_mismatch', hwid, ip, cert_fp });
        return res.status(403).json({ ok: false, error: 'hwid mismatch' });
      }
    }

    // Success
    logEvent({ key_id: row.id, key_text: keyText, event: 'validated', hwid, ip, cert_fp });

    const payload = {
      id: row.id,
      group: row.group_name,
      expires_at: row.expires_at,
      server_time: nowSeconds()
    };
    const encrypted = aesEncrypt(payload);

    return res.json({ ok: true, message: 'valid', token: encrypted });
  } catch (err) {
    console.error('=== VALIDATE ERROR ===');
    console.error('Error:', err);
    console.error('Stack:', err.stack);
    console.error('Request body:', req.body);
    console.error('=====================');
    return res.status(500).json({ ok: false, error: 'server error', details: process.env.NODE_ENV === 'development' ? err.message : undefined });
  }
});

// ---------- Admin Dashboard APIs ----------
app.post('/admin/key/add', adminGuard, adminLimiter, (req, res) => {
  try {
    const { 
      group='DEFAULT', 
      lifetimeSeconds = 86400 * 30, 
      bindOnFirstUse = true, 
      allowedIps = [], 
      allowedCertFPs = [], 
      extra = {} 
    } = req.body || {};

    const keyText = generateKeyToken({ group, lifetimeSeconds });
    const id = uuidv4();
    const created = nowSeconds();
    const expires = created + Number(lifetimeSeconds || 0);

    db.prepare(`INSERT INTO keys (
      id, key_text, group_name, created_at, expires_at, time_length_seconds, 
      bind_on_first_use, bound_hwid, allowed_ips, allowed_cert_fps, extra
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      id, keyText, group, created, expires, lifetimeSeconds, 
      bindOnFirstUse ? 1 : 0, null, 
      JSON.stringify(allowedIps || []), 
      JSON.stringify(allowedCertFPs || []), 
      JSON.stringify(extra || {})
    );

    logEvent({ 
      key_id: id, 
      key_text: keyText, 
      event: 'created', 
      hwid: null, 
      ip: req.ip, 
      cert_fp: req.headers[CERT_FP_HEADER] || null 
    });

    return res.json({ ok: true, key: keyText, id, group, expires_at: expires });
  } catch (err) {
    console.error('add key error', err);
    return res.status(500).json({ ok:false, error:'server error' });
  }
});

app.post('/admin/key/remove', adminGuard, adminLimiter, (req, res) => {
  const { key, id } = req.body || {};
  if (!key && !id) return res.status(400).json({ ok:false, error:'key or id required' });
  
  let row;
  if (id) row = db.prepare('SELECT * FROM keys WHERE id = ?').get(id);
  else row = db.prepare('SELECT * FROM keys WHERE key_text = ?').get(key);
  
  if (!row) return res.status(404).json({ ok:false, error:'not found' });
  
  db.prepare('DELETE FROM keys WHERE id = ?').run(row.id);
  logEvent({ 
    key_id: row.id, 
    key_text: row.key_text, 
    event: 'deleted', 
    hwid:null, 
    ip: req.ip, 
    cert_fp: req.headers[CERT_FP_HEADER] || null 
  });
  
  return res.json({ ok:true, deleted: row.id });
});

app.post('/admin/key/reset-hwid', adminGuard, adminLimiter, (req, res) => {
  const { key, id } = req.body || {};
  if (!key && !id) return res.status(400).json({ ok:false, error:'key or id required' });
  
  let row;
  if (id) row = db.prepare('SELECT * FROM keys WHERE id = ?').get(id);
  else row = db.prepare('SELECT * FROM keys WHERE key_text = ?').get(key);
  
  if (!row) return res.status(404).json({ ok:false, error:'not found' });
  
  db.prepare('UPDATE keys SET bound_hwid = NULL WHERE id = ?').run(row.id);
  logEvent({ 
    key_id: row.id, 
    key_text: row.key_text, 
    event: 'hwid_unbound', 
    hwid:null, 
    ip: req.ip, 
    cert_fp: req.headers[CERT_FP_HEADER] || null 
  });
  
  return res.json({ ok:true, id: row.id, message: 'hwid unbound' });
});

app.get('/admin/keys', adminGuard, (req, res) => {
  const limit = Math.min(200, Number(req.query.limit || 50));
  const offset = Number(req.query.offset || 0);
  const rows = db.prepare(
    'SELECT id, key_text, group_name, created_at, expires_at, bind_on_first_use, bound_hwid FROM keys ORDER BY created_at DESC LIMIT ? OFFSET ?'
  ).all(limit, offset);
  return res.json({ ok:true, keys: rows });
});

app.get('/admin/key/:id', adminGuard, (req, res) => {
  const id = req.params.id;
  const row = db.prepare('SELECT * FROM keys WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ ok:false, error:'not found' });
  
  try {
    row.allowed_ips = JSON.parse(row.allowed_ips || '[]');
    row.allowed_cert_fps = JSON.parse(row.allowed_cert_fps || '[]');
    row.extra = JSON.parse(row.extra || '{}');
  } catch (e) {
    console.error('parse error:', e);
  }
  
  return res.json({ ok:true, key: row });
});

app.post('/admin/key/update', adminGuard, adminLimiter, (req, res) => {
  const { id, allowedIps, allowedCertFPs, expiresAt, bindOnFirstUse } = req.body || {};
  if (!id) return res.status(400).json({ ok:false, error:'id required' });
  
  const row = db.prepare('SELECT * FROM keys WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ ok:false, error:'not found' });

  const stmt = db.prepare(
    `UPDATE keys SET allowed_ips = ?, allowed_cert_fps = ?, expires_at = ?, bind_on_first_use = ? WHERE id = ?`
  );
  stmt.run(
    allowedIps !== undefined ? JSON.stringify(allowedIps) : row.allowed_ips,
    allowedCertFPs !== undefined ? JSON.stringify(allowedCertFPs) : row.allowed_cert_fps,
    expiresAt !== undefined ? Number(expiresAt) : row.expires_at,
    bindOnFirstUse !== undefined ? (bindOnFirstUse ? 1 : 0) : row.bind_on_first_use,
    id
  );
  
  logEvent({ 
    key_id: id, 
    key_text: row.key_text, 
    event: 'updated', 
    hwid:null, 
    ip:req.ip, 
    cert_fp: req.headers[CERT_FP_HEADER] || null 
  });
  
  return res.json({ ok:true, id });
});

// ---------- Health Check ----------
app.get('/', (req, res) => {
  res.json({ 
    ok:true, 
    server_time: nowSeconds(), 
    env: process.env.NODE_ENV || 'production' 
  });
});

// ---------- Start Server ----------
app.listen(PORT, () => {
  console.log(`Key auth server listening on port ${PORT}`);
  console.log(`DB: ${DB_PATH}`);
});