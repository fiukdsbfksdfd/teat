/**
 * Key Auth Server - PostgreSQL Version
 * 
 * Uses PostgreSQL for persistent storage on Render
 * Set DATABASE_URL environment variable with your Render PostgreSQL connection string
 */

const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const AES_KEY_B64 = process.env.AES_KEY;
const HMAC_KEY_B64 = process.env.HMAC_KEY;
const ADMIN_IP = process.env.ADMIN_IP || null;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || null;
const CERT_FP_HEADER = process.env.CERT_FINGERPRINT_HEADER || 'x-client-cert-fp';

if (!DATABASE_URL) {
  console.error('ERROR: DATABASE_URL environment variable is required.');
  console.error('Get it from your Render PostgreSQL database dashboard.');
  process.exit(1);
}

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

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const app = express();
app.set('trust proxy', true);
app.use(helmet());
app.use(bodyParser.json({ limit: '200kb' }));
app.use(cors());
app.use(morgan('combined'));

// Rate limiters
const validateLimiter = rateLimit({
  windowMs: 10 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip || 'unknown',
  skip: (req) => process.env.NODE_ENV === 'development',
  handler: (req, res) => res.status(429).json({ ok: false, error: 'Too many requests' })
});

const adminLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip || 'unknown',
  skip: (req) => process.env.NODE_ENV === 'development',
  handler: (req, res) => res.status(429).json({ ok: false, error: 'Too many admin requests' })
});

// Initialize Database
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS keys (
        id TEXT PRIMARY KEY,
        key_text TEXT UNIQUE NOT NULL,
        group_name TEXT,
        created_at BIGINT,
        expires_at BIGINT,
        time_length_seconds INTEGER,
        bind_on_first_use BOOLEAN DEFAULT true,
        bound_hwid TEXT,
        allowed_ips JSONB,
        allowed_cert_fps JSONB,
        extra JSONB
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS logs (
        id SERIAL PRIMARY KEY,
        key_id TEXT,
        key_text TEXT,
        event TEXT,
        hwid TEXT,
        ip TEXT,
        cert_fp TEXT,
        created_at BIGINT
      )
    `);

    console.log('✅ Database initialized');
  } catch (err) {
    console.error('Database initialization error:', err);
    process.exit(1);
  }
}

// Utilities
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

function makeRandomSegment(len = 8) {
  return crypto.randomBytes(len).toString('hex').toUpperCase();
}

function normalizeIP(ip) {
  return ip.replace(/^::ffff:/i, '');
}

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
    
    const expNum = Number(exp);
    if (!Number.isInteger(expNum) || expNum < 0) return null;
    if (!/^[0-9a-fA-F]+$/.test(sig)) return null;
    
    const payload = `${group}-${random}-${exp}`;
    const expected = hmacSign(payload);
    
    let validSig = false;
    try {
      if (sig.length === expected.length && sig.length === 64) {
        const sigBuf = Buffer.from(sig, 'hex');
        const expBuf = Buffer.from(expected, 'hex');
        if (sigBuf.length === 32 && expBuf.length === 32) {
          validSig = crypto.timingSafeEqual(sigBuf, expBuf);
        }
      }
    } catch (e) {
      validSig = false;
    }
    
    return { validSig, group, random, exp: expNum, sig, rawPayload: payload };
  } catch (err) {
    return null;
  }
}

async function logEvent({ key_id=null, key_text=null, event, hwid=null, ip=null, cert_fp=null }) {
  try {
    await pool.query(
      `INSERT INTO logs (key_id, key_text, event, hwid, ip, cert_fp, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [key_id, key_text, event, hwid, ip, cert_fp, nowSeconds()]
    );
  } catch (err) {
    console.error('logEvent error:', err);
  }
}

// Middlewares
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

// Public API
app.post('/validate', validateLimiter, async (req, res) => {
  try {
    const { key: keyText, hwid } = req.body || {};
    const ip = normalizeIP(req.ip || req.connection.remoteAddress);
    const certFp = req.headers[CERT_FP_HEADER] || null;

    console.log(`[VALIDATE] Key: ${keyText}, HWID: ${hwid}, IP: ${ip}`);

    if (!keyText) return res.status(400).json({ ok: false, error: 'key required' });

    const parsed = parseKeyToken(keyText);
    console.log('[VALIDATE] Parsed:', parsed);
    
    if (!parsed || !parsed.validSig) {
      await logEvent({ key_text: keyText, event: 'invalid_format', hwid, ip, cert_fp: certFp });
      return res.status(401).json({ ok: false, error: 'invalid signature or format' });
    }

    if (parsed.exp && parsed.exp < nowSeconds()) {
      await logEvent({ key_text: keyText, event: 'expired_token', hwid, ip, cert_fp: certFp });
      return res.status(403).json({ ok: false, error: 'key expired (token-level)' });
    }

    const result = await pool.query('SELECT * FROM keys WHERE key_text = $1', [keyText]);
    const row = result.rows[0];
    
    if (!row) {
      await logEvent({ key_text: keyText, event: 'not_found', hwid, ip, cert_fp: certFp });
      return res.status(404).json({ ok: false, error: 'key not registered' });
    }

    if (row.expires_at && row.expires_at < nowSeconds()) {
      await logEvent({ key_id: row.id, key_text: keyText, event: 'expired', hwid, ip, cert_fp: certFp });
      return res.status(403).json({ ok: false, error: 'key expired' });
    }

    // IP check
    if (row.allowed_ips && Array.isArray(row.allowed_ips) && row.allowed_ips.length > 0) {
      const allowedNormalized = row.allowed_ips.map(a => normalizeIP(a.trim()));
      if (!allowedNormalized.includes(ip)) {
        await logEvent({ key_id: row.id, key_text: keyText, event: 'ip_blocked', hwid, ip, cert_fp: certFp });
        return res.status(403).json({ ok: false, error: 'IP not allowed for this key' });
      }
    }

    // Cert check
    if (row.allowed_cert_fps && Array.isArray(row.allowed_cert_fps) && row.allowed_cert_fps.length > 0) {
      if (!certFp || !row.allowed_cert_fps.includes(certFp)) {
        await logEvent({ key_id: row.id, key_text: keyText, event: 'cert_blocked', hwid, ip, cert_fp: certFp });
        return res.status(403).json({ ok: false, error: 'certificate fingerprint not allowed' });
      }
    }

    // HWID handling
    if (row.bind_on_first_use) {
      if (!row.bound_hwid) {
        if (!hwid) {
          await logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_required_bind', hwid, ip, cert_fp: certFp });
          return res.status(400).json({ ok:false, error: 'hwid required to bind key' });
        }
        await pool.query('UPDATE keys SET bound_hwid = $1 WHERE id = $2', [hwid, row.id]);
        await logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_bound', hwid, ip, cert_fp: certFp });
        row.bound_hwid = hwid;
      } else {
        if (hwid && hwid !== row.bound_hwid) {
          await logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_mismatch', hwid, ip, cert_fp: certFp });
          return res.status(403).json({ ok: false, error: 'hwid mismatch' });
        }
        if (!hwid) {
          await logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_missing', hwid, ip, cert_fp: certFp });
          return res.status(400).json({ ok:false, error: 'hwid required' });
        }
      }
    } else if (row.bound_hwid) {
      if (!hwid) {
        await logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_missing', hwid, ip, cert_fp: certFp });
        return res.status(400).json({ ok:false, error: 'hwid required' });
      }
      if (hwid !== row.bound_hwid) {
        await logEvent({ key_id: row.id, key_text: keyText, event: 'hwid_mismatch', hwid, ip, cert_fp: certFp });
        return res.status(403).json({ ok: false, error: 'hwid mismatch' });
      }
    }

    await logEvent({ key_id: row.id, key_text: keyText, event: 'validated', hwid, ip, cert_fp: certFp });

    const payload = {
      id: row.id,
      group: row.group_name,
      expires_at: row.expires_at,
      bound_hwid: row.bound_hwid,
      server_time: nowSeconds()
    };
    const encrypted = aesEncrypt(payload);

    console.log('[VALIDATE SUCCESS]', { key_id: row.id, group: row.group_name });

    return res.json({ 
      ok: true, 
      message: 'valid', 
      token: encrypted,
      group: row.group_name,
      expires_at: row.expires_at
    });
  } catch (err) {
    console.error('=== VALIDATE ERROR ===', err);
    return res.status(500).json({ ok: false, error: 'server error' });
  }
});

// Admin APIs
app.post('/admin/key/add', adminGuard, adminLimiter, async (req, res) => {
  try {
    const { group='DEFAULT', lifetimeSeconds = 86400 * 30, bindOnFirstUse = true, allowedIps = [], allowedCertFPs = [], extra = {} } = req.body || {};

    const keyText = generateKeyToken({ group, lifetimeSeconds });
    const id = uuidv4();
    const created = nowSeconds();
    const expires = created + Number(lifetimeSeconds || 0);

    await pool.query(
      `INSERT INTO keys (id, key_text, group_name, created_at, expires_at, time_length_seconds, bind_on_first_use, allowed_ips, allowed_cert_fps, extra) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [id, keyText, group, created, expires, lifetimeSeconds, bindOnFirstUse, JSON.stringify(allowedIps), JSON.stringify(allowedCertFPs), JSON.stringify(extra)]
    );

    await logEvent({ key_id: id, key_text: keyText, event: 'created', ip: req.ip });

    return res.json({ ok: true, key: keyText, id, group, expires_at: expires });
  } catch (err) {
    console.error('add key error', err);
    return res.status(500).json({ ok:false, error:'server error' });
  }
});

app.get('/admin/keys', adminGuard, async (req, res) => {
  const limit = Math.min(200, Number(req.query.limit || 50));
  const offset = Number(req.query.offset || 0);
  const result = await pool.query(
    'SELECT id, key_text, group_name, created_at, expires_at, bind_on_first_use, bound_hwid FROM keys ORDER BY created_at DESC LIMIT $1 OFFSET $2',
    [limit, offset]
  );
  return res.json({ ok:true, keys: result.rows });
});

app.get('/', (req, res) => {
  res.json({ ok:true, server_time: nowSeconds(), database: 'PostgreSQL' });
});

// Start server
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ Key auth server (PostgreSQL) listening on port ${PORT}`);
    console.log(`✅ Database: ${DATABASE_URL.split('@')[1]}`);
  });
});