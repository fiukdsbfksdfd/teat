/**
 * Key Auth Server - MongoDB Version
 *
 * Features:
 * - AES-256-GCM helpers for encrypting payloads
 * - HWID binding and reset
 * - IP checks
 * - Optional cert fingerprint check
 * - Admin dashboard routes locked by ADMIN_IP and ADMIN_API_KEY
 */

const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const crypto = require('crypto');
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

const PORT = process.env.PORT || 3000;
const AES_KEY_B64 = process.env.AES_KEY;
const HMAC_KEY_B64 = process.env.HMAC_KEY;
const ADMIN_IP = process.env.ADMIN_IP || null;
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || null;
const CERT_FP_HEADER = process.env.CERT_FINGERPRINT_HEADER || 'x-client-cert-fp';
const MONGO_URI = process.env.MONGO_URI;

if (!AES_KEY_B64 || !HMAC_KEY_B64 || !MONGO_URI) {
  console.error('ERROR: AES_KEY, HMAC_KEY, and MONGO_URI environment variables are required.');
  process.exit(1);
}

const AES_KEY = Buffer.from(AES_KEY_B64.replace(/^base64:/, ''), 'base64');
const HMAC_KEY = Buffer.from(HMAC_KEY_B64.replace(/^base64:/, ''), 'base64');

if (AES_KEY.length !== 32) {
  console.error('ERROR: AES_KEY must be 32 bytes (base64-encoded).');
  process.exit(1);
}

// ---------- MongoDB Setup ----------
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

const keySchema = new mongoose.Schema({
  key_text: { type: String, unique: true },
  group_name: String,
  created_at: Number,
  expires_at: Number,
  bind_on_first_use: { type: Boolean, default: true },
  bound_hwid: String,
  allowed_ips: [String],
  allowed_cert_fps: [String],
  extra: mongoose.Schema.Types.Mixed
});

const logSchema = new mongoose.Schema({
  key_id: String,
  key_text: String,
  event: String,
  hwid: String,
  ip: String,
  cert_fp: String,
  created_at: Number
});

const Key = mongoose.model('Key', keySchema);
const Log = mongoose.model('Log', logSchema);

// ---------- Utilities ----------
function nowSeconds() { return Math.floor(Date.now() / 1000); }
function hmacSign(data) { return crypto.createHmac('sha256', HMAC_KEY).update(data).digest('hex'); }

function aesEncrypt(obj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
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

function normalizeIP(ip) { return ip.replace(/^::ffff:/i, ''); }

function generateKeyToken({ group='DEFAULT', lifetimeSeconds = 86400 * 30 }) {
  const random = makeRandomSegment(6);
  const exp = nowSeconds() + lifetimeSeconds;
  const payload = `${group}-${random}-${exp}`;
  const sig = hmacSign(payload);
  return `${payload}-${sig}`;
}

function parseKeyToken(token) {
  try {
    if (!token) return null;
    const parts = token.split('-');
    if (parts.length < 4) return null;
    const sig = parts.pop();
    const exp = Number(parts.pop());
    const group = parts.shift();
    const random = parts.join('-');
    const payload = `${group}-${random}-${exp}`;
    const expected = hmacSign(payload);
    let validSig = false;
    try {
      if (sig.length === expected.length) {
        validSig = crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
      }
    } catch (e) { validSig = false; }
    return { validSig, group, random, exp, sig, rawPayload: payload };
  } catch (err) { return null; }
}

async function logEvent({ key_id=null, key_text=null, event, hwid=null, ip=null, cert_fp=null }) {
  try {
    await Log.create({ key_id, key_text, event, hwid, ip, cert_fp, created_at: nowSeconds() });
  } catch (err) {
    console.error('logEvent error:', err);
  }
}

// Helper to format key document for response
function formatKeyResponse(doc) {
  return {
    id: doc._id.toString(),
    key_text: doc.key_text,
    group_name: doc.group_name,
    created_at: doc.created_at,
    expires_at: doc.expires_at,
    bind_on_first_use: doc.bind_on_first_use,
    bound_hwid: doc.bound_hwid || null,
    allowed_ips: doc.allowed_ips || [],
    allowed_cert_fps: doc.allowed_cert_fps || [],
    extra: doc.extra || {}
  };
}

// ---------- Express Setup ----------
const app = express();
app.set('trust proxy', true);
app.use(helmet());
app.use(bodyParser.json({ limit: '200kb' }));
app.use(cors());
app.use(morgan('combined'));

// ---------- Rate Limiters ----------
const validateLimiter = rateLimit({
  windowMs: 10*1000, max:50,
  standardHeaders:true, legacyHeaders:false,
  keyGenerator: req => req.ip || 'unknown',
  skip: () => process.env.NODE_ENV === 'development',
  handler: (req,res)=>res.status(429).json({ ok:false, error:'Too many requests' })
});
const adminLimiter = rateLimit({
  windowMs: 60*1000, max:100,
  standardHeaders:true, legacyHeaders:false,
  keyGenerator: req=>req.ip||'unknown',
  skip: ()=>process.env.NODE_ENV==='development',
  handler:(req,res)=>res.status(429).json({ ok:false, error:'Too many admin requests' })
});

// ---------- Admin Guard ----------
function adminGuard(req,res,next){
  const requesterIp = normalizeIP(req.ip || req.connection.remoteAddress);
  const normalizedAdminIp = ADMIN_IP ? normalizeIP(ADMIN_IP) : null;
  if(normalizedAdminIp && requesterIp!==normalizedAdminIp)
    return res.status(401).json({ error:'Admin IP not allowed' });
  const incoming = req.headers['x-admin-api-key'] || req.query.adminApiKey || req.body?.adminApiKey;
  if(!ADMIN_API_KEY || incoming!==ADMIN_API_KEY) return res.status(401).json({ error:'Admin API key required' });
  next();
}

// ---------- Public API ----------
app.post('/validate', validateLimiter, async (req,res)=>{
  try{
    const { key: keyText, hwid } = req.body || {};
    const ip = normalizeIP(req.ip||'unknown');
    const certFp = req.headers[CERT_FP_HEADER] || null;

    if(!keyText) return res.status(400).json({ ok:false, error:'key required' });

    const parsed = parseKeyToken(keyText);
    if(!parsed || !parsed.validSig){
      await logEvent({ key_text:keyText, event:'invalid_format', hwid, ip, cert_fp:certFp });
      return res.status(401).json({ ok:false, error:'invalid signature or format' });
    }

    if(parsed.exp && parsed.exp<nowSeconds()){
      await logEvent({ key_text:keyText, event:'expired_token', hwid, ip, cert_fp:certFp });
      return res.status(403).json({ ok:false, error:'key expired (token-level)' });
    }

    const row = await Key.findOne({ key_text:keyText });
    if(!row){
      await logEvent({ key_text:keyText, event:'not_found', hwid, ip, cert_fp:certFp });
      return res.status(404).json({ ok:false, error:'key not registered' });
    }

    if(row.expires_at && row.expires_at<nowSeconds()){
      await logEvent({ key_id:row._id, key_text:keyText, event:'expired', hwid, ip, cert_fp:certFp });
      return res.status(403).json({ ok:false, error:'key expired' });
    }

    // IP check
    if(row.allowed_ips?.length && !row.allowed_ips.includes(ip)){
      await logEvent({ key_id:row._id, key_text:keyText, event:'ip_blocked', hwid, ip, cert_fp:certFp });
      return res.status(403).json({ ok:false, error:'IP not allowed for this key' });
    }

    // Cert fingerprint check
    if(row.allowed_cert_fps?.length && (!certFp || !row.allowed_cert_fps.includes(certFp))){
      await logEvent({ key_id:row._id, key_text:keyText, event:'cert_blocked', hwid, ip, cert_fp:certFp });
      return res.status(403).json({ ok:false, error:'certificate fingerprint not allowed' });
    }

    // HWID binding
    if(row.bind_on_first_use && !row.bound_hwid){
      if(!hwid){
        await logEvent({ key_id:row._id, key_text:keyText, event:'hwid_required_bind', hwid, ip, cert_fp:certFp });
        return res.status(400).json({ ok:false, error:'hwid required to bind key' });
      }
      row.bound_hwid = hwid;
      await row.save();
      await logEvent({ key_id:row._id, key_text:keyText, event:'hwid_bound', hwid, ip, cert_fp:certFp });
    } else if(row.bound_hwid && hwid && hwid!==row.bound_hwid){
      await logEvent({ key_id:row._id, key_text:keyText, event:'hwid_mismatch', hwid, ip, cert_fp:certFp });
      return res.status(403).json({ ok:false, error:'hwid mismatch' });
    }

    // Success
    await logEvent({ key_id:row._id, key_text:keyText, event:'validated', hwid, ip, cert_fp:certFp });
    const payload = {
      id: row._id,
      group: row.group_name,
      expires_at: row.expires_at,
      bound_hwid: row.bound_hwid,
      server_time: nowSeconds()
    };
    return res.json({ ok:true, message:'valid', token:aesEncrypt(payload), group:row.group_name, expires_at:row.expires_at });
  }catch(err){
    console.error('=== VALIDATE ERROR ===', err);
    return res.status(500).json({ ok:false, error:'server error' });
  }
});

// ---------- Admin API ----------
app.post('/admin/key/add', adminGuard, adminLimiter, async (req,res)=>{
  try{
    const { group='DEFAULT', lifetimeSeconds=86400*30, bindOnFirstUse=true, allowedIps=[], allowedCertFPs=[], extra={} } = req.body || {};
    const keyText = generateKeyToken({ group, lifetimeSeconds });
    const created = nowSeconds();
    const expires = created + Number(lifetimeSeconds||0);

    const key = await Key.create({
      key_text: keyText,
      group_name: group,
      created_at: created,
      expires_at: expires,
      bind_on_first_use: bindOnFirstUse,
      bound_hwid: null,
      allowed_ips: allowedIps,
      allowed_cert_fps: allowedCertFPs,
      extra
    });

    await logEvent({ key_id:key._id, key_text:keyText, event:'created', ip:req.ip, cert_fp:req.headers[CERT_FP_HEADER]||null });
    return res.json({ ok:true, key:keyText, id:key._id.toString(), group, expires_at:expires });
  }catch(err){ console.error(err); return res.status(500).json({ ok:false, error:'server error' }); }
});

app.post('/admin/key/remove', adminGuard, adminLimiter, async (req,res)=>{
  try {
    const { key, id } = req.body || {};
    if(!key && !id) return res.status(400).json({ ok:false, error:'key or id required' });
    const row = id ? await Key.findById(id) : await Key.findOne({ key_text:key });
    if(!row) return res.status(404).json({ ok:false, error:'not found' });
    await Key.deleteOne({ _id: row._id });
    await logEvent({ key_id:row._id, key_text:row.key_text, event:'deleted', ip:req.ip, cert_fp:req.headers[CERT_FP_HEADER]||null });
    return res.json({ ok:true, deleted:row._id.toString() });
  } catch(err) { 
    console.error(err); 
    return res.status(500).json({ ok:false, error:'server error' }); 
  }
});

app.post('/admin/key/reset-hwid', adminGuard, adminLimiter, async (req,res)=>{
  try {
    const { key, id } = req.body || {};
    if(!key && !id) return res.status(400).json({ ok:false, error:'key or id required' });
    const row = id ? await Key.findById(id) : await Key.findOne({ key_text:key });
    if(!row) return res.status(404).json({ ok:false, error:'not found' });
    
    row.bound_hwid = null;
    await row.save();
    
    await logEvent({ key_id:row._id, key_text:row.key_text, event:'hwid_reset', ip:req.ip, cert_fp:req.headers[CERT_FP_HEADER]||null });
    return res.json({ ok:true, message:'HWID reset', key_id:row._id.toString() });
  } catch(err) { 
    console.error(err); 
    return res.status(500).json({ ok:false, error:'server error' }); 
  }
});

app.post('/admin/key/update', adminGuard, adminLimiter, async (req,res)=>{
  try {
    const { id, allowedIps, allowedCertFPs, expiresAt, bindOnFirstUse } = req.body || {};
    if(!id) return res.status(400).json({ ok:false, error:'id required' });
    
    const row = await Key.findById(id);
    if(!row) return res.status(404).json({ ok:false, error:'not found' });
    
    if(allowedIps !== undefined) row.allowed_ips = allowedIps;
    if(allowedCertFPs !== undefined) row.allowed_cert_fps = allowedCertFPs;
    if(expiresAt !== undefined) row.expires_at = expiresAt;
    if(bindOnFirstUse !== undefined) row.bind_on_first_use = bindOnFirstUse;
    
    await row.save();
    await logEvent({ key_id:row._id, key_text:row.key_text, event:'updated', ip:req.ip, cert_fp:req.headers[CERT_FP_HEADER]||null });
    
    return res.json({ ok:true, message:'Key updated', key: formatKeyResponse(row) });
  } catch(err) { 
    console.error(err); 
    return res.status(500).json({ ok:false, error:'server error' }); 
  }
});

app.get('/admin/key/:id', adminGuard, adminLimiter, async (req,res)=>{
  try {
    const { id } = req.params;
    const row = await Key.findById(id);
    if(!row) return res.status(404).json({ ok:false, error:'not found' });
    
    return res.json({ ok:true, key: formatKeyResponse(row) });
  } catch(err) { 
    console.error(err); 
    return res.status(500).json({ ok:false, error:'server error' }); 
  }
});

app.get('/admin/keys', adminGuard, adminLimiter, async (req,res)=>{
  try {
    const limit = parseInt(req.query.limit) || 50;
    const offset = parseInt(req.query.offset) || 0;
    
    const keys = await Key.find().skip(offset).limit(limit).sort({ created_at: -1 });
    const total = await Key.countDocuments();
    
    return res.json({ 
      ok:true, 
      keys: keys.map(formatKeyResponse),
      total,
      limit,
      offset
    });
  } catch(err) { 
    console.error(err); 
    return res.status(500).json({ ok:false, error:'server error' }); 
  }
});

// ---------- Health Check ----------
app.get('/', (req,res)=>{
  res.json({ ok:true, server_time:nowSeconds(), env:process.env.NODE_ENV||'production' });
});

// ---------- Start Server ----------
app.listen(PORT, ()=>console.log(`Key auth server listening on port ${PORT}`));