// routes.js – All Express routes and middleware
const express = require('express');
const { Server } = require('socket.io');
const session = require('express-session');
const passport = require('passport'); // if needed
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const morgan = require('morgan');
const responseTime = require('response-time');
const xss = require('xss-clean');
const hpp = require('hpp');
const QRCode = require('qrcode');
const bcrypt = require('bcryptjs');
const JavaScriptObfuscator = require('javascript-obfuscator');
const { body, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');
const { createBullBoard } = require('@bull-board/api');
const { BullAdapter } = require('@bull-board/api/bullAdapter');
const { ExpressAdapter } = require('@bull-board/express');

const {
  CONFIG,
  getDbPool,
  getRedis,
  getSessionStore,
  getQueues,
  getKeyManager,
  getTxManager,
  getBreakerMonitor,
  getStats,
  getCaches,
  logger,
  parseTTL,
  formatDuration,
  validateUrl,
  isLikelyBot,
  getCountryCode,
  generateShortLink,
  generateLongLink,
  decodeLongLink,
  RequestSigner,
  InputValidator,
  APIVersionManager,
  advancedMultiLayerEncode
} = require('./core');

// ==================== INITIALIZE MIDDLEWARE COMPONENTS ====================
const requestSigner = new RequestSigner(CONFIG.REQUEST_SIGNING_SECRET);
const validator = new InputValidator();
const apiVersionManager = new APIVersionManager();
const { redirectQueue, emailQueue, analyticsQueue, encodingQueue } = getQueues();

// Rate limiters
const rateLimiterMiddleware = (req, res, next) => {
  const key = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown';
  // use flexible rate limiter if Redis available else memory
  // ... implementation
  next();
};
const strictLimiter = rateLimit({ windowMs: CONFIG.RATE_LIMIT_WINDOW, max: (req) => req.deviceInfo?.isBot ? CONFIG.RATE_LIMIT_BOT : (req.deviceInfo?.isMobile ? CONFIG.RATE_LIMIT_MOBILE : CONFIG.RATE_LIMIT_MAX_REQUESTS) });
const encodingLimiter = rateLimit({ windowMs: 60000, max: CONFIG.ENCODING_RATE_LIMIT });
const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 5, skipSuccessfulRequests: true });

// CSRF protection
const csrfProtection = (req, res, next) => {
  if (['GET','HEAD','OPTIONS'].includes(req.method)) return next();
  const token = req.body._csrf || req.headers['x-csrf-token'] || req.cookies['XSRF-TOKEN'];
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  next();
};

// Auth middleware for admin
const ensureAuthenticated = (req, res, next) => {
  if (!req.session.authenticated) return res.redirect('/admin/login');
  next();
};

// ==================== CREATE EXPRESS APP & SOCKET.IO ====================
function createServer(app, server) {
  // --- Middleware setup (order matters) ---
  app.set('trust proxy', CONFIG.TRUST_PROXY);
  app.use(compression({ level: 6, threshold: 1024 }));
  app.use(morgan(CONFIG.LOG_FORMAT === 'json' ? 'combined' : 'dev'));
  app.use(express.static('public', { maxAge: '7d' }));
  app.use(express.json({ limit: '100kb' }));
  app.use(express.urlencoded({ extended: true, limit: '100kb' }));
  app.use(cookieParser(CONFIG.SESSION_SECRET));
  app.use(cors({ origin: CONFIG.CORS_ORIGIN === '*' ? '*' : CONFIG.CORS_ORIGIN.split(','), credentials: true }));
  app.use(xss());
  app.use(hpp());
  
  // Session
  const sessionConfig = {
    store: getSessionStore(),
    secret: CONFIG.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    name: 'redirector.sid',
    cookie: { secure: CONFIG.NODE_ENV === 'production' && CONFIG.HTTPS_ENABLED, maxAge: CONFIG.SESSION_TTL * 1000, httpOnly: true, sameSite: 'lax' }
  };
  app.use(session(sessionConfig));
  
  // Request ID & context
  app.use((req, res, next) => { req.id = uuidv4(); res.setHeader('X-Request-ID', req.id); next(); });
  
  // Device detection & bot detection helper
  app.use((req, res, next) => {
    req.deviceInfo = { type: 'desktop', isBot: false, score: 0 }; // simplified
    next();
  });
  
  // Rate limiting
  app.use(rateLimiterMiddleware);
  app.use(strictLimiter);
  
  // CSRF token generation
  app.use((req, res, next) => {
    if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    res.cookie('XSRF-TOKEN', req.session.csrfToken, { httpOnly: false, sameSite: 'lax' });
    next();
  });
  
  // Request signing (for API v2)
  app.use(requestSigner.signRequest.bind(requestSigner));
  
  // --- Socket.IO ---
  const io = new Server(server, { cors: { origin: CONFIG.CORS_ORIGIN }, path: '/socket.io/' });
  io.of('/admin').use((socket, next) => {
    const sessionId = socket.handshake.auth.sessionId;
    if (sessionId) {
      getSessionStore().get(sessionId, (err, sess) => {
        if (err || !sess?.authenticated) return next(new Error('Unauthorized'));
        socket.session = sess;
        next();
      });
    } else next(new Error('No session'));
  });
  io.of('/admin').on('connection', (socket) => {
    socket.emit('stats', getStats());
    socket.on('command', async (cmd) => { /* handle admin commands */ });
  });
  
  // --- Bull Board (queue monitoring) ---
  let serverAdapter;
  if (CONFIG.BULL_BOARD_ENABLED && redirectQueue) {
    serverAdapter = new ExpressAdapter();
    serverAdapter.setBasePath(CONFIG.BULL_BOARD_PATH);
    createBullBoard({ queues: [new BullAdapter(redirectQueue), new BullAdapter(encodingQueue)], serverAdapter });
    app.use(CONFIG.BULL_BOARD_PATH, ensureAuthenticated, serverAdapter.getRouter());
  }
  
  // --- API Versioning ---
  const v1Router = express.Router();
  const v2Router = express.Router();
  
  // v1 routes
  v1Router.post('/generate', csrfProtection, encodingLimiter, async (req, res, next) => {
    // ... original v1 generate logic
    try {
      const target = req.body.url || CONFIG.TARGET_URL;
      if (!validateUrl(target)) throw new Error('Invalid URL');
      const linkMode = req.body.linkMode || CONFIG.LINK_LENGTH_MODE;
      let result;
      if (linkMode === 'long') {
        result = await generateLongLink(target, req, { segments: CONFIG.LONG_LINK_SEGMENTS, params: CONFIG.LONG_LINK_PARAMS });
      } else {
        result = generateShortLink(target, req);
      }
      const cacheId = result.metadata.id || crypto.createHash('md5').update(result.url).digest('hex');
      const linkData = { target, created: Date.now(), expiresAt: Date.now() + LINK_TTL_SEC*1000, currentClicks: 0, linkMode };
      getCaches().linkCache.set(cacheId, linkData, LINK_TTL_SEC);
      // store in DB if available
      res.json({ url: result.url, id: cacheId, mode: linkMode });
    } catch (err) { next(err); }
  });
  
  v1Router.get('/stats/:id', async (req, res, next) => { /* ... */ });
  
  // v2 routes (with request signature)
  v2Router.use(requestSigner.verifySignature);
  v2Router.post('/generate', encodingLimiter, async (req, res, next) => { /* similar but with validated body */ });
  v2Router.post('/bulk', async (req, res, next) => { /* ... */ });
  v2Router.get('/stats/:id', async (req, res, next) => { /* ... */ });
  
  apiVersionManager.registerVersion('v1', v1Router);
  apiVersionManager.registerVersion('v2', v2Router);
  app.use('/api', apiVersionManager.versionMiddleware());
  app.use('/api/v1', v1Router);
  app.use('/api/v2', v2Router);
  
  // --- Public redirect endpoints ---
  app.get('/v/:id', strictLimiter, async (req, res, next) => {
    // original /v/:id logic
    const linkId = req.params.id;
    const data = getCaches().linkCache.get(linkId);
    if (!data) return res.redirect('/expired');
    if (data.expiresAt < Date.now()) return res.redirect('/expired');
    // password check, bot detection, etc.
    res.redirect(data.target);
  });
  
  app.get('/r/*', strictLimiter, async (req, res, next) => {
    const decodeResult = await decodeLongLink(req);
    if (decodeResult.success) res.redirect(decodeResult.target);
    else res.redirect(CONFIG.TARGET_URL);
  });
  
  // --- Admin routes ---
  app.get('/admin/login', (req, res) => { /* serve login page */ });
  app.post('/admin/login', loginLimiter, csrfProtection, async (req, res) => {
    const { username, password } = req.body;
    if (username === CONFIG.ADMIN_USERNAME && await bcrypt.compare(password, CONFIG.ADMIN_PASSWORD_HASH)) {
      req.session.authenticated = true;
      req.session.user = username;
      res.json({ success: true });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
  app.get('/admin', ensureAuthenticated, (req, res) => { /* serve dashboard */ });
  app.post('/admin/clear-cache', ensureAuthenticated, (req, res) => {
    Object.values(getCaches()).forEach(cache => cache.flushAll());
    res.json({ success: true });
  });
  // ... other admin endpoints (settings, keys, export, etc.)
  
  // --- Health & Metrics ---
  app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));
  app.get('/metrics', async (req, res) => {
    const apiKey = req.headers['x-api-key'];
    if (apiKey !== CONFIG.METRICS_API_KEY) return res.status(403).json({ error: 'Forbidden' });
    res.set('Content-Type', require('prom-client').register.contentType);
    res.send(await require('prom-client').register.metrics());
  });
  
  // --- QR code endpoints ---
  app.get('/qr', async (req, res) => { /* ... */ });
  
  // --- Fallback ---
  app.use((req, res) => res.redirect(CONFIG.BOT_URLS[0]));
  
  // --- Global error handler ---
  app.use((err, req, res, next) => {
    logger.error(err);
    res.status(err.statusCode || 500).json({ error: err.message, id: req.id });
  });
  
  return { app, io };
}

module.exports = { createServer };
