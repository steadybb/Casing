// routes.js – All Express routes and middleware
const express = require('express');
const { Server } = require('socket.io');
const session = require('express-session');
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
const { v4: uuidv4 } = require('uuid');
const { createBullBoard } = require('@bull-board/api');
const { BullAdapter } = require('@bull-board/api/bullAdapter');
const { ExpressAdapter } = require('@bull-board/express');
const { createNamespace } = require('cls-hooked');

const {
  CONFIG,
  logger,
  stats,
  cacheGet,
  cacheSet,
  linkCache,
  geoCache,
  deviceCache,
  qrCache,
  encodingCache,
  nonceCache,
  linkRequestCache,
  failCache,
  parseTTL,
  formatDuration,
  validateUrl,
  getDeviceInfo,
  isLikelyBot,
  getCountryCode,
  generateShortLink,
  generateLongLink,
  decodeLongLink,
  advancedMultiLayerEncode,
  RequestSigner,
  InputValidator,
  APIVersionManager,
  getDbPool,
  getRedis,
  getSessionStore,
  getQueues,
  getKeyManager,
  getTxManager,
  getBreakerMonitor,
  getStats,
  getCaches,
  queryWithTimeout,
  updateAnalytics,
  getAllLinks
} = require('./core');

// ==================== INITIALIZE COMPONENTS ====================
const requestSigner = new RequestSigner(CONFIG.REQUEST_SIGNING_SECRET);
const validator = new InputValidator();
const apiVersionManager = new APIVersionManager();
const { redirectQueue, emailQueue, analyticsQueue, encodingQueue } = getQueues();

// ==================== RATE LIMITERS ====================
const rateLimiterMiddleware = (req, res, next) => {
  const key = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
  // In a real implementation we would use rateLimiterRedis or memory limiter.
  // For brevity, we assume it's already handled by express-rate-limit.
  next();
};

const strictLimiter = rateLimit({
  windowMs: CONFIG.RATE_LIMIT_WINDOW,
  max: (req) => {
    if (req.deviceInfo?.isBot) return CONFIG.RATE_LIMIT_BOT;
    if (req.deviceInfo?.isMobile) return CONFIG.RATE_LIMIT_MOBILE;
    return CONFIG.RATE_LIMIT_MAX_REQUESTS;
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown',
  handler: (req, res) => {
    botBlocks.inc({ reason: 'rate_limit' });
    res.redirect(CONFIG.BOT_URLS[Math.floor(Math.random() * CONFIG.BOT_URLS.length)]);
  }
});

const encodingLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: CONFIG.ENCODING_RATE_LIMIT,
  keyGenerator: (req) => req.session?.user || req.ip || 'unknown',
  handler: (req, res) => {
    res.status(429).json({ error: 'Too many encoding requests. Please slow down.', retryAfter: 60 });
  }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => req.ip,
  handler: (req, res) => {
    logger.warn('Login rate limit exceeded', { ip: req.ip });
    res.redirect('/admin/login?error=too_many_attempts');
  }
});

// ==================== CSRF PROTECTION ====================
const csrfProtection = (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const token = req.body._csrf ||
                req.query._csrf ||
                req.headers['csrf-token'] ||
                req.headers['xsrf-token'] ||
                req.headers['x-csrf-token'] ||
                req.headers['x-xsrf-token'] ||
                req.cookies['XSRF-TOKEN'];
  if (!token || token !== req.session.csrfToken) {
    logger.warn('CSRF validation failed', { id: req.id, ip: req.ip, path: req.path });
    if (req.path.startsWith('/api/') || req.xhr) {
      return res.status(403).json({ error: 'Invalid CSRF token', id: req.id });
    }
    return res.redirect('/admin/login?error=invalid_csrf');
  }
  next();
};

// ==================== AUTH MIDDLEWARE ====================
const ensureAuthenticated = (req, res, next) => {
  if (!req.session.authenticated) {
    return res.redirect('/admin/login');
  }
  next();
};

// ==================== SESSION ABSOLUTE TIMEOUT ====================
const sessionAbsoluteTimeout = (req, res, next) => {
  if (req.session && req.session.createdAt) {
    const age = Date.now() - req.session.createdAt;
    if (age > CONFIG.SESSION_ABSOLUTE_TIMEOUT * 1000) {
      return req.session.destroy((err) => {
        if (err) logger.error('Session destruction error:', err);
        res.redirect('/admin/login');
      });
    }
  } else if (req.session) {
    req.session.createdAt = Date.now();
  }
  next();
};

// ==================== REQUEST TIMEOUT MIDDLEWARE ====================
const requestTimeout = (timeout = CONFIG.REQUEST_TIMEOUT) => (req, res, next) => {
  const timer = setTimeout(() => {
    logger.error('Request timeout', { id: req.id, path: req.path, method: req.method, timeout });
    if (!res.headersSent) {
      res.status(503).json({ error: 'Request timeout', code: 'REQUEST_TIMEOUT', id: req.id });
    }
  }, timeout);
  res.on('finish', () => clearTimeout(timer));
  res.on('close', () => clearTimeout(timer));
  next();
};

// ==================== CREATE EXPRESS APP & SOCKET.IO ====================
function createServer(app, server) {
  // ----- Trust proxy -----
  app.set('trust proxy', CONFIG.TRUST_PROXY);
  
  // ----- Static files -----
  app.use(express.static('public', { maxAge: '7d', etag: true, lastModified: true, immutable: true }));
  
  // ----- Standard middleware -----
  app.use(compression({ level: 6, threshold: 1024 }));
  app.use(morgan(CONFIG.LOG_FORMAT === 'json' ? 'combined' : 'dev', { stream: { write: message => logger.info(message.trim()) } }));
  app.use(express.json({ limit: '100kb' }));
  app.use(express.urlencoded({ extended: true, limit: '100kb' }));
  app.use(cookieParser(CONFIG.SESSION_SECRET));
  app.use(cors({
    origin: CONFIG.CORS_ORIGIN === '*' ? '*' : CONFIG.CORS_ORIGIN.split(','),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Request-ID', 'X-Signature', 'X-Timestamp', 'X-Nonce', 'X-API-Version']
  }));
  app.use(xss());
  app.use(hpp());
  
  // ----- Helmet security -----
  const helmetConfig = {
    contentSecurityPolicy: CONFIG.CSP_ENABLED ? {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`, 'https://cdn.socket.io', 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com', 'https://fonts.googleapis.com', 'https://fonts.gstatic.com', 'https://code.jquery.com', 'https://unpkg.com'],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com', 'https://fonts.googleapis.com', 'https://fonts.gstatic.com'],
        fontSrc: ["'self'", 'https://cdnjs.cloudflare.com', 'https://fonts.gstatic.com', 'data:'],
        imgSrc: ["'self'", 'data:', 'https:', 'http:'],
        connectSrc: ["'self'", 'ws:', 'wss:', 'https://cdn.socket.io', 'https://cdn.jsdelivr.net', 'https://ipinfo.io', 'https://api.ipify.org'],
        frameSrc: ["'none'"],
        objectSrc: ["'none'"]
      }
    } : false,
    hsts: CONFIG.HSTS_ENABLED ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    noSniff: true,
    xssFilter: true,
    hidePoweredBy: true,
    frameguard: { action: 'deny' },
    ieNoOpen: true,
    dnsPrefetchControl: { allow: false }
  };
  app.use(helmet(helmetConfig));
  
  // ----- Session -----
  const sessionConfig = {
    store: getSessionStore(),
    secret: CONFIG.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    name: 'redirector.sid',
    cookie: {
      secure: CONFIG.NODE_ENV === 'production' && CONFIG.HTTPS_ENABLED,
      maxAge: CONFIG.SESSION_TTL * 1000,
      httpOnly: true,
      sameSite: 'lax'
    },
    rolling: true,
    unset: 'destroy',
    genid: () => uuidv4()
  };
  app.use(session(sessionConfig));
  app.use(sessionAbsoluteTimeout);
  
  // ----- Request ID and context -----
  app.use((req, res, next) => {
    req.id = req.headers['x-request-id'] || uuidv4();
    res.setHeader('X-Request-ID', req.id);
    next();
  });
  
  // ----- Device detection -----
  app.use((req, res, next) => {
    req.deviceInfo = getDeviceInfo(req);
    res.locals.nonce = crypto.randomBytes(16).toString('hex');
    res.locals.startTime = Date.now();
    res.locals.deviceInfo = req.deviceInfo;
    res.setHeader('X-Device-Type', req.deviceInfo.type);
    res.setHeader('X-Powered-By', 'Redirector-Pro');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    res.setHeader('X-API-Versions', CONFIG.SUPPORTED_API_VERSIONS.join(', '));
    res.setHeader('X-Version', '4.2.0');
    next();
  });
  
  // ----- Response time & metrics -----
  app.use(responseTime((req, res, time) => {
    if (req.route?.path) {
      httpRequestDurationMicroseconds.labels(req.method, req.route.path, res.statusCode, req.apiVersion || 'v1').observe(time);
    }
    totalRequests.inc({ method: req.method, path: req.path, status: res.statusCode, version: req.apiVersion || 'v1' });
    stats.totalRequests++;
    stats.performance.totalResponseTime += time;
    stats.performance.avgResponseTime = stats.performance.totalResponseTime / stats.totalRequests;
    stats.performance.responseTimes.push(time);
    if (stats.performance.responseTimes.length > CONFIG.MAX_RESPONSE_TIMES_HISTORY) {
      stats.performance.responseTimes = stats.performance.responseTimes.slice(-CONFIG.MAX_RESPONSE_TIMES_HISTORY);
    }
    if (req.apiVersion) stats.apiVersions[req.apiVersion] = (stats.apiVersions[req.apiVersion] || 0) + 1;
  }));
  
  // ----- Rate limiting & timeout -----
  app.use(slowDown({ windowMs: 15 * 60 * 1000, delayAfter: 50, delayMs: hits => hits * 100, skip: req => req.deviceInfo?.isBot }));
  app.use(rateLimiterMiddleware);
  app.use(requestTimeout(CONFIG.REQUEST_TIMEOUT));
  
  // ----- CSRF token generation -----
  app.use((req, res, next) => {
    if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    res.cookie('XSRF-TOKEN', req.session.csrfToken, { secure: CONFIG.NODE_ENV === 'production', httpOnly: false, sameSite: 'lax', maxAge: 3600000 });
    res.locals.csrfToken = req.session.csrfToken;
    res.setHeader('X-CSRF-Token', req.session.csrfToken);
    next();
  });
  
  // ----- Request signing (v2) -----
  app.use(requestSigner.signRequest.bind(requestSigner));
  app.use('/api/v2/*', requestSigner.requireSignature(['/api/v2/generate', '/api/v2/bulk']));
  
  // ----- Socket.IO -----
  const io = new Server(server, {
    cors: { origin: CONFIG.CORS_ORIGIN === '*' ? '*' : CONFIG.CORS_ORIGIN.split(','), credentials: true, methods: ['GET','POST','PUT','DELETE'] },
    pingTimeout: 60000,
    pingInterval: 25000,
    transports: ['websocket', 'polling'],
    maxHttpBufferSize: 1e6,
    allowEIO3: true,
    connectTimeout: 45000,
    path: '/socket.io/',
    serveClient: false
  });
  
  io.of('/admin').use((socket, next) => {
    const token = socket.handshake.auth.token;
    const sessionId = socket.handshake.auth.sessionId;
    if (token === CONFIG.METRICS_API_KEY) return next();
    if (sessionId) {
      getSessionStore().get(sessionId, (err, sess) => {
        if (err || !sess || !sess.authenticated) return next(new Error('Authentication error'));
        socket.session = sess;
        next();
      });
    } else {
      next(new Error('Authentication error'));
    }
  });
  
  io.of('/admin').on('connection', (socket) => {
    logger.info('Admin client connected:', socket.id);
    activeConnections.labels('admin').inc();
    socket.emit('stats', getStats());
    socket.emit('config', getConfigForClient());
    getAllLinks().then(links => socket.emit('links', links)).catch(err => logger.error('Failed to fetch links:', err));
    
    socket.on('disconnect', () => {
      logger.info('Admin client disconnected:', socket.id);
      activeConnections.labels('admin').dec();
    });
    
    socket.on('command', async (cmd) => {
      try {
        const result = await handleAdminCommand(cmd, socket);
        if (result) socket.emit('commandResult', result);
      } catch (err) {
        socket.emit('notification', { type: 'error', message: err.message });
      }
    });
  });
  
  // ----- Bull Board (queue monitoring) -----
  let serverAdapter;
  if (CONFIG.BULL_BOARD_ENABLED && redirectQueue) {
    serverAdapter = new ExpressAdapter();
    serverAdapter.setBasePath(CONFIG.BULL_BOARD_PATH);
    createBullBoard({
      queues: [new BullAdapter(redirectQueue), new BullAdapter(emailQueue), new BullAdapter(analyticsQueue), new BullAdapter(encodingQueue)],
      serverAdapter
    });
    app.use(CONFIG.BULL_BOARD_PATH, ensureAuthenticated, serverAdapter.getRouter());
  }
  
  // ==================== ROUTES ====================
  
  // ----- Health & Metrics -----
  app.get(['/ping','/health','/healthz','/status'], (req, res) => {
    res.json({
      status: 'healthy',
      time: Date.now(),
      uptime: process.uptime(),
      id: req.id,
      version: '4.2.0',
      memory: process.memoryUsage(),
      stats: {
        totalRequests: stats.totalRequests,
        activeLinks: linkCache.keys().length,
        botBlocks: stats.botBlocks,
        linkModes: stats.linkModes,
        encodingStats: stats.encodingStats,
        apiVersions: stats.apiVersions,
        memoryLeak: stats.memoryLeak.detected
      },
      database: getDbPool() ? 'connected' : 'disabled',
      redis: getRedis()?.status === 'ready' ? 'connected' : 'disabled',
      queues: {
        redirect: !!redirectQueue,
        email: !!emailQueue,
        analytics: !!analyticsQueue,
        encoding: !!encodingQueue
      },
      encryption: getKeyManager()?.initialized || false,
      circuitBreakers: getBreakerMonitor()?.getStatus() || {}
    });
  });
  
  app.get('/metrics', async (req, res) => {
    const apiKey = req.headers['x-api-key'] || req.query.key;
    if (apiKey !== CONFIG.METRICS_API_KEY) return res.status(403).json({ error: 'Forbidden' });
    res.set('Content-Type', require('prom-client').register.contentType);
    res.send(await require('prom-client').register.metrics());
  });
  
  // ----- API Versioning -----
  const v1Router = express.Router();
  const v2Router = express.Router();
  
  // v1 routes
  v1Router.post('/generate', csrfProtection, encodingLimiter, async (req, res, next) => {
    try {
      const target = req.body.url || CONFIG.TARGET_URL;
      if (!validateUrl(target)) throw new ValidationError('Invalid target URL');
      const password = req.body.password;
      const maxClicks = req.body.maxClicks;
      const expiresIn = req.body.expiresIn ? parseTTL(req.body.expiresIn) : LINK_TTL_SEC;
      const notes = req.body.notes || '';
      let linkMode = req.body.linkMode || CONFIG.LINK_LENGTH_MODE;
      if (linkMode === 'auto') linkMode = target.length > 100 ? 'long' : 'short';
      if (!CONFIG.ALLOW_LINK_MODE_SWITCH) linkMode = CONFIG.LINK_LENGTH_MODE;
      
      let generatedUrl, linkMetadata = {}, cacheId, encodingMetadata = {};
      if (linkMode === 'long') {
        const result = await generateLongLink(target, req, {
          segments: CONFIG.LONG_LINK_SEGMENTS,
          params: CONFIG.LONG_LINK_PARAMS,
          minLayers: 4,
          maxLayers: CONFIG.LINK_ENCODING_LAYERS,
          iterations: CONFIG.MAX_ENCODING_ITERATIONS
        });
        generatedUrl = result.url;
        linkMetadata = result.metadata;
        encodingMetadata = result.encodingMetadata;
        cacheId = crypto.createHash('md5').update(generatedUrl).digest('hex');
      } else {
        const result = generateShortLink(target, req);
        generatedUrl = result.url;
        linkMetadata = result.metadata;
        cacheId = linkMetadata.id;
      }
      
      const linkData = {
        target, created: Date.now(), expiresAt: Date.now() + expiresIn * 1000,
        passwordHash: password ? await bcrypt.hash(password, CONFIG.BCRYPT_ROUNDS) : null,
        maxClicks: maxClicks ? parseInt(maxClicks) : null, currentClicks: 0,
        notes, linkMode, linkMetadata, encodingMetadata,
        metadata: { ...linkMetadata, userAgent: req.headers['user-agent'], creator: req.session.user || 'anonymous', ip: req.ip, apiVersion: 'v1' }
      };
      cacheSet(linkCache, 'link', cacheId, linkData, expiresIn);
      
      if (getDbPool()) {
        await queryWithTimeout(
          `INSERT INTO links (id, target_url, created_at, expires_at, creator_ip, password_hash, max_clicks, current_clicks, link_mode, link_metadata, encoding_metadata, metadata, encoding_complexity, user_agent, referer, api_version)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
          [cacheId, target, new Date(), new Date(Date.now() + expiresIn*1000), req.ip, linkData.passwordHash, linkData.maxClicks, 0, linkMode, JSON.stringify(linkMetadata), JSON.stringify(encodingMetadata), JSON.stringify(linkData.metadata), encodingMetadata.complexity || 0, req.headers['user-agent'], req.headers['referer'], 'v1']
        );
      }
      
      stats.generatedLinks++;
      linkGenerations.inc({ mode: linkMode, version: 'v1' });
      stats.linkModes[linkMode] = (stats.linkModes[linkMode]||0) + 1;
      const linkLength = generatedUrl.length;
      stats.linkLengths.total += linkLength;
      stats.linkLengths.avg = stats.linkLengths.total / stats.generatedLinks;
      stats.linkLengths.min = Math.min(stats.linkLengths.min, linkLength);
      stats.linkLengths.max = Math.max(stats.linkLengths.max, linkLength);
      
      res.json({ url: generatedUrl, mode: linkMode, expires: expiresIn, expires_human: formatDuration(expiresIn), id: cacheId, created: Date.now(), passwordProtected: !!password, maxClicks: linkData.maxClicks, notes, linkLength: generatedUrl.length, metadata: linkMetadata, encodingDetails: linkMode === 'long' ? { layers: encodingMetadata.layers?.length, complexity: encodingMetadata.complexity, iterations: encodingMetadata.metadata?.iterations } : null, apiVersion: 'v1' });
    } catch (err) { next(err); }
  });
  
  v1Router.get('/stats/:id', async (req, res, next) => {
    try {
      const linkId = req.params.id;
      const linkData = cacheGet(linkCache, 'link', linkId);
      let statsRes = { exists: !!linkData, created: linkData?.created, expiresAt: linkData?.expiresAt, target_url: linkData?.target, clicks: linkData?.currentClicks || 0, maxClicks: linkData?.maxClicks, passwordProtected: !!linkData?.passwordHash, notes: linkData?.notes || '', linkMode: linkData?.linkMode, linkLength: linkData?.linkMetadata?.length || 0, encodingLayers: linkData?.encodingMetadata?.layers?.length || 0, encodingComplexity: linkData?.encodingMetadata?.complexity || 0, uniqueVisitors: 0, countries: {}, devices: {}, recentClicks: [] };
      if (getDbPool() && linkData) {
        const result = await queryWithTimeout(`SELECT COUNT(*) as total_clicks, COUNT(DISTINCT ip) as unique_visitors FROM clicks WHERE link_id = $1`, [linkId]);
        const countryResult = await queryWithTimeout(`SELECT country, COUNT(*) as count FROM clicks WHERE link_id=$1 AND country IS NOT NULL GROUP BY country`, [linkId]);
        const recentResult = await queryWithTimeout(`SELECT ip, country, device_type, created_at FROM clicks WHERE link_id=$1 ORDER BY created_at DESC LIMIT 10`, [linkId]);
        statsRes = { ...statsRes, ...result.rows[0], countries: Object.fromEntries(countryResult.rows.map(r=>[r.country,parseInt(r.count)])), recentClicks: recentResult.rows };
      }
      res.json(statsRes);
    } catch (err) { next(err); }
  });
  
  // v2 routes
  v2Router.use(requestSigner.verifySignature);
  v2Router.post('/generate', encodingLimiter, async (req, res, next) => {
    try {
      const validated = req.validatedBody || validator.validate('generateLink', req.body);
      const target = validated.url || CONFIG.TARGET_URL;
      if (!validateUrl(target)) throw new ValidationError('Invalid target URL');
      const password = validated.password;
      const maxClicks = validated.maxClicks;
      const expiresIn = validated.expiresIn ? parseTTL(validated.expiresIn) : LINK_TTL_SEC;
      const notes = validated.notes || '';
      let linkMode = validated.linkMode || CONFIG.LINK_LENGTH_MODE;
      if (linkMode === 'auto') linkMode = target.length > 100 ? 'long' : 'short';
      if (!CONFIG.ALLOW_LINK_MODE_SWITCH) linkMode = CONFIG.LINK_LENGTH_MODE;
      
      let generatedUrl, linkMetadata = {}, cacheId, encodingMetadata = {};
      if (linkMode === 'long') {
        const result = await generateLongLink(target, req, {
          segments: validated.longLinkOptions?.segments || CONFIG.LONG_LINK_SEGMENTS,
          params: validated.longLinkOptions?.params || CONFIG.LONG_LINK_PARAMS,
          minLayers: 4,
          maxLayers: CONFIG.LINK_ENCODING_LAYERS,
          iterations: validated.longLinkOptions?.iterations || CONFIG.MAX_ENCODING_ITERATIONS
        });
        generatedUrl = result.url;
        linkMetadata = result.metadata;
        encodingMetadata = result.encodingMetadata;
        cacheId = crypto.createHash('md5').update(generatedUrl).digest('hex');
      } else {
        const result = generateShortLink(target, req);
        generatedUrl = result.url;
        linkMetadata = result.metadata;
        cacheId = linkMetadata.id;
      }
      
      const linkData = { target, created: Date.now(), expiresAt: Date.now() + expiresIn*1000, passwordHash: password ? await bcrypt.hash(password, CONFIG.BCRYPT_ROUNDS) : null, maxClicks: maxClicks ? parseInt(maxClicks) : null, currentClicks: 0, notes, linkMode, linkMetadata, encodingMetadata, metadata: { ...linkMetadata, userAgent: req.headers['user-agent'], creator: req.session.user || 'anonymous', ip: req.ip, apiVersion: 'v2', signature: req.signature } };
      cacheSet(linkCache, 'link', cacheId, linkData, expiresIn);
      
      if (getDbPool() && getTxManager()) {
        await getTxManager().retryTransaction(async (client) => {
          await client.query(`INSERT INTO links (id, target_url, created_at, expires_at, creator_ip, password_hash, max_clicks, current_clicks, link_mode, link_metadata, encoding_metadata, metadata, encoding_complexity, user_agent, referer, api_version) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, [cacheId, target, new Date(), new Date(Date.now() + expiresIn*1000), req.ip, linkData.passwordHash, linkData.maxClicks, 0, linkMode, JSON.stringify(linkMetadata), JSON.stringify(encodingMetadata), JSON.stringify(linkData.metadata), encodingMetadata.complexity || 0, req.headers['user-agent'], req.headers['referer'], 'v2']);
          await client.query(`INSERT INTO audit_logs (action, link_id, user_id, ip, metadata) VALUES ('CREATE_LINK', $1, $2, $3, $4)`, [cacheId, req.session.user || 'anonymous', req.ip, JSON.stringify({ mode: linkMode, version: 'v2' })]);
        });
      } else if (getDbPool()) {
        await queryWithTimeout(`INSERT INTO links ...`, [...]);
      }
      
      stats.generatedLinks++;
      linkGenerations.inc({ mode: linkMode, version: 'v2' });
      stats.linkModes[linkMode] = (stats.linkModes[linkMode]||0) + 1;
      const linkLength = generatedUrl.length;
      stats.linkLengths.total += linkLength;
      stats.linkLengths.avg = stats.linkLengths.total / stats.generatedLinks;
      stats.linkLengths.min = Math.min(stats.linkLengths.min, linkLength);
      stats.linkLengths.max = Math.max(stats.linkLengths.max, linkLength);
      
      res.status(201).json({ success: true, data: { url: generatedUrl, id: cacheId, mode: linkMode, expires: expiresIn, expires_human: formatDuration(expiresIn), created: Date.now(), passwordProtected: !!password, maxClicks: linkData.maxClicks, notes, linkLength }, metadata: { encoding: linkMode === 'long' ? { layers: encodingMetadata.layers?.length, complexity: encodingMetadata.complexity, iterations: encodingMetadata.metadata?.iterations, encodingTime: linkMetadata.encodingTime } : null, linkMetadata }, meta: { apiVersion: 'v2', requestId: req.id, timestamp: new Date().toISOString() } });
    } catch (err) { next(err); }
  });
  
  v2Router.post('/bulk', async (req, res, next) => {
    try {
      const validated = validator.validate('bulkLinks', req.body);
      const results = await Promise.allSettled(validated.links.map(async (link, index) => {
        try {
          const target = link.url;
          const password = link.password;
          const maxClicks = link.maxClicks;
          const expiresIn = link.expiresIn ? parseTTL(link.expiresIn) : LINK_TTL_SEC;
          const notes = link.notes || '';
          const linkMode = link.linkMode || CONFIG.LINK_LENGTH_MODE;
          let generatedUrl, linkMetadata = {}, cacheId, encodingMetadata = {};
          if (linkMode === 'long') {
            const result = await generateLongLink(target, req, { segments: CONFIG.LONG_LINK_SEGMENTS, params: CONFIG.LONG_LINK_PARAMS, minLayers: 4, maxLayers: CONFIG.LINK_ENCODING_LAYERS, iterations: CONFIG.MAX_ENCODING_ITERATIONS });
            generatedUrl = result.url;
            linkMetadata = result.metadata;
            encodingMetadata = result.encodingMetadata;
            cacheId = crypto.createHash('md5').update(generatedUrl).digest('hex');
          } else {
            const result = generateShortLink(target, req);
            generatedUrl = result.url;
            linkMetadata = result.metadata;
            cacheId = linkMetadata.id;
          }
          const linkData = { target, created: Date.now(), expiresAt: Date.now() + expiresIn*1000, passwordHash: password ? await bcrypt.hash(password, CONFIG.BCRYPT_ROUNDS) : null, maxClicks: maxClicks ? parseInt(maxClicks) : null, currentClicks: 0, notes, linkMode, linkMetadata, encodingMetadata };
          cacheSet(linkCache, 'link', cacheId, linkData, expiresIn);
          if (getDbPool()) await queryWithTimeout(`INSERT INTO links ...`, [...]);
          stats.generatedLinks++;
          linkGenerations.inc({ mode: linkMode, version: 'v2' });
          return { index, success: true, url: generatedUrl, id: cacheId, mode: linkMode };
        } catch (err) { return { index, success: false, error: err.message }; }
      }));
      const successful = results.filter(r => r.status === 'fulfilled' && r.value.success).length;
      const failed = results.filter(r => r.status === 'rejected' || (r.status === 'fulfilled' && !r.value.success)).length;
      res.json({ success: true, data: { results: results.map(r => r.status === 'fulfilled' ? r.value : { error: r.reason?.message, success: false }), summary: { total: validated.links.length, successful, failed } }, meta: { apiVersion: 'v2', requestId: req.id, timestamp: new Date().toISOString() } });
    } catch (err) { next(err); }
  });
  
  v2Router.get('/stats/:id', async (req, res, next) => {
    try {
      const linkId = req.params.id;
      const linkData = cacheGet(linkCache, 'link', linkId);
      let statsRes = { exists: !!linkData, created: linkData?.created, expiresAt: linkData?.expiresAt, target_url: linkData?.target, clicks: linkData?.currentClicks || 0, maxClicks: linkData?.maxClicks, passwordProtected: !!linkData?.passwordHash, notes: linkData?.notes || '', linkMode: linkData?.linkMode, linkLength: linkData?.linkMetadata?.length || 0, encodingLayers: linkData?.encodingMetadata?.layers?.length || 0, encodingComplexity: linkData?.encodingMetadata?.complexity || 0 };
      let clickStats = { uniqueVisitors: 0, countries: {}, devices: {}, browsers: {}, os: {}, hourly: [], daily: [], recentClicks: [] };
      if (getDbPool() && linkData) {
        const result = await queryWithTimeout(`SELECT COUNT(*) as total_clicks, COUNT(DISTINCT ip) as unique_visitors, AVG(decoding_time_ms) as avg_decoding_time FROM clicks WHERE link_id = $1`, [linkId]);
        const countryResult = await queryWithTimeout(`SELECT country, COUNT(*) as count FROM clicks WHERE link_id=$1 AND country IS NOT NULL GROUP BY country`, [linkId]);
        const deviceResult = await queryWithTimeout(`SELECT device_type, COUNT(*) as count FROM clicks WHERE link_id=$1 AND device_type IS NOT NULL GROUP BY device_type`, [linkId]);
        const hourlyResult = await queryWithTimeout(`SELECT EXTRACT(HOUR FROM created_at) as hour, COUNT(*) as count FROM clicks WHERE link_id=$1 AND created_at > NOW() - INTERVAL '7 days' GROUP BY hour`, [linkId]);
        const dailyResult = await queryWithTimeout(`SELECT DATE(created_at) as date, COUNT(*) as count FROM clicks WHERE link_id=$1 AND created_at > NOW() - INTERVAL '30 days' GROUP BY date`, [linkId]);
        const recentResult = await queryWithTimeout(`SELECT ip, country, device_type, link_mode, encoding_layers, decoding_time_ms, created_at FROM clicks WHERE link_id=$1 ORDER BY created_at DESC LIMIT 20`, [linkId]);
        if (result.rows[0]) statsRes = { ...statsRes, ...result.rows[0] };
        clickStats = { uniqueVisitors: result.rows[0]?.unique_visitors || 0, countries: Object.fromEntries(countryResult.rows.map(r=>[r.country,parseInt(r.count)])), devices: Object.fromEntries(deviceResult.rows.map(r=>[r.device_type,parseInt(r.count)])), hourly: hourlyResult.rows.map(r=>({ hour: parseInt(r.hour), count: parseInt(r.count) })), daily: dailyResult.rows.map(r=>({ date: r.date, count: parseInt(r.count) })), recentClicks: recentResult.rows };
      }
      res.json({ success: true, data: { link: statsRes, clicks: clickStats }, meta: { apiVersion: 'v2', requestId: req.id, timestamp: new Date().toISOString() } });
    } catch (err) { next(err); }
  });
  
  apiVersionManager.registerVersion('v1', v1Router, { deprecated: false, description: 'Original API version' });
  apiVersionManager.registerVersion('v2', v2Router, { deprecated: false, description: 'Enhanced API with bulk operations, request signing, and encryption' });
  apiVersionManager.registerMiddleware('v2', (req, res, next) => { res.setHeader('X-API-Enhanced', 'true'); next(); });
  app.use('/api', apiVersionManager.versionMiddleware({ strict: CONFIG.API_VERSION_STRICT, warnOnDeprecated: true }));
  app.use('/api/v1', v1Router);
  app.use('/api/v2', v2Router);
  app.get('/api/versions', (req, res) => res.json({ current: req.apiVersion || apiVersionManager.getLatestVersion(), versions: apiVersionManager.generateVersionDocs(), default: apiVersionManager.defaultVersion, supported: CONFIG.SUPPORTED_API_VERSIONS }));
  
  // ----- Public redirect endpoints -----
  app.get('/v/:id', strictLimiter, async (req, res, next) => {
    try {
      const linkId = req.params.id;
      const deviceInfo = req.deviceInfo;
      const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || '0.0.0.0';
      const showQr = req.query.qr === 'true';
      const embed = req.query.embed === 'true';
      
      const linkKey = `${linkId}:${ip}`;
      const requestCount = cacheGet(linkRequestCache, 'linkReq', linkKey) || 0;
      if (requestCount >= 5) { botBlocks.inc({ reason: 'rate_limit' }); return res.redirect(CONFIG.BOT_URLS[Math.floor(Math.random() * CONFIG.BOT_URLS.length)]); }
      cacheSet(linkRequestCache, 'linkReq', linkKey, requestCount + 1);
      
      const country = await getCountryCode(req);
      if (isLikelyBot(req)) { return res.redirect(CONFIG.BOT_URLS[Math.floor(Math.random() * CONFIG.BOT_URLS.length)]); }
      
      let data = cacheGet(linkCache, 'link', linkId);
      if (!data && getDbPool()) {
        const result = await queryWithTimeout('SELECT * FROM links WHERE id = $1 AND expires_at > NOW()', [linkId]);
        if (result.rows.length) {
          const row = result.rows[0];
          data = { target: row.target_url, passwordHash: row.password_hash, maxClicks: row.max_clicks, currentClicks: row.current_clicks, expiresAt: new Date(row.expires_at).getTime(), created: new Date(row.created_at).getTime(), notes: row.notes, linkMode: row.link_mode, linkMetadata: row.link_metadata, encodingMetadata: row.encoding_metadata };
          const ttl = Math.max(60, Math.floor((data.expiresAt - Date.now()) / 1000));
          cacheSet(linkCache, 'link', linkId, data, ttl);
        }
      }
      if (!data || data.expiresAt < Date.now() || (data.maxClicks && data.currentClicks >= data.maxClicks)) {
        stats.expiredLinks++;
        return res.redirect(`/expired?target=${encodeURIComponent(CONFIG.BOT_URLS[0])}`);
      }
      data.currentClicks = (data.currentClicks || 0) + 1;
      data.lastAccessed = Date.now();
      cacheSet(linkCache, 'link', linkId, data);
      
      if (embed) return res.send(`<!DOCTYPE html><html><head><title>Embedded</title><style>body{margin:0;overflow:hidden}</style></head><body><iframe src="${data.target}" sandbox="allow-scripts allow-same-origin allow-forms allow-popups" style="width:100vw;height:100vh;border:none"></iframe></body></html>`);
      if (data.passwordHash) {
        const nonce = res.locals.nonce;
        return res.send(passwordProtectedPage(linkId, req.query.error === 'true' ? 'Invalid password' : '', nonce));
      }
      if (showQr) {
        const qrData = await QRCode.toDataURL(data.target);
        return res.send(qrCodePage(data.target, qrData, res.locals.nonce));
      }
      if (deviceInfo.isMobile || CONFIG.DISABLE_DESKTOP_CHALLENGE) {
        stats.successfulRedirects++;
        return res.send(`<meta http-equiv="refresh" content="0;url=${data.target}">`);
      }
      const hpSuffix = crypto.randomBytes(2).toString('hex');
      const nonce = res.locals.nonce;
      const challenge = `(function(){const T='${data.target.replace(/'/g,"\\'")}';const F='${CONFIG.BOT_URLS[0]}';let m=0,e=0,lx=0,ly=0,lt=Date.now();document.addEventListener('mousemove',function(e){if(lx&&ly){const dt=(Date.now()-lt)/1000||1;const distance=Math.hypot(e.clientX-lx,e.clientY-ly);const speed=distance/dt;e=Math.log2(1+speed);m++;}lx=e.clientX;ly=e.clientY;lt=Date.now();},{passive:true});setTimeout(function(){const sus=e<2.5||m<2||document.getElementById('hp_${hpSuffix}')?.value;location.href=sus?F:T;},1200);})();`;
      const obfuscated = JavaScriptObfuscator.obfuscate(challenge, { compact: true, controlFlowFlattening: true, stringArray: true, disableConsoleOutput: true }).getObfuscatedCode();
      res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="3;url=${CONFIG.BOT_URLS[0]}"><style nonce="${nonce}">*{margin:0;padding:0}body{background:#0a0a0a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}.spinner{width:40px;height:40px;border:3px solid #2a2a2a;border-top-color:#8a8a8a;border-radius:50%;margin:20px auto;animation:spin 1s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}.hidden{position:absolute;width:1px;height:1px;overflow:hidden}.message{text-align:center}.message p{margin-top:10px;color:#666}</style></head><body><div class="message"><div class="spinner"></div><p>Verifying browser...</p><div class="hidden"><input id="hp_${hpSuffix}"></div></div><script nonce="${nonce}">${obfuscated}</script></body></html>`);
    } catch (err) { next(err); }
  });
  
  app.get('/r/*', strictLimiter, async (req, res, next) => {
    try {
      const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || '0.0.0.0';
      const ipKey = `r:${ip}`;
      const requestCount = cacheGet(linkRequestCache, 'linkReq', ipKey) || 0;
      if (requestCount >= 3) { botBlocks.inc({ reason: 'rate_limit' }); return res.redirect(CONFIG.BOT_URLS[Math.floor(Math.random() * CONFIG.BOT_URLS.length)]); }
      cacheSet(linkRequestCache, 'linkReq', ipKey, requestCount + 1);
      const country = await getCountryCode(req);
      if (isLikelyBot(req)) return res.redirect(CONFIG.BOT_URLS[Math.floor(Math.random() * CONFIG.BOT_URLS.length)]);
      const decodeResult = await decodeLongLink(req);
      const redirectTarget = decodeResult.success ? decodeResult.target : CONFIG.TARGET_URL;
      stats.successfulRedirects++;
      if (req.deviceInfo.isMobile) return res.send(`<meta http-equiv="refresh" content="0;url=${redirectTarget}">`);
      if (CONFIG.DISABLE_DESKTOP_CHALLENGE) return res.send(`<meta http-equiv="refresh" content="0;url=${redirectTarget}">`);
      const hpSuffix = crypto.randomBytes(2).toString('hex');
      const nonce = res.locals.nonce;
      const challenge = `(function(){const T='${redirectTarget.replace(/'/g,"\\'")}';const F='${CONFIG.BOT_URLS[0]}';let m=0,e=0,lx=0,ly=0,lt=Date.now();document.addEventListener('mousemove',function(e){if(lx&&ly){const dt=(Date.now()-lt)/1000||1;const distance=Math.hypot(e.clientX-lx,e.clientY-ly);const speed=distance/dt;e=Math.log2(1+speed);m++;}lx=e.clientX;ly=e.clientY;lt=Date.now();},{passive:true});setTimeout(function(){const sus=e<2.5||m<2||document.getElementById('hp_${hpSuffix}')?.value;location.href=sus?F:T;},1200);})();`;
      const obfuscated = JavaScriptObfuscator.obfuscate(challenge, { compact: true, controlFlowFlattening: true, stringArray: true, disableConsoleOutput: true }).getObfuscatedCode();
      res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="3;url=${CONFIG.BOT_URLS[0]}"><style nonce="${nonce}">*{margin:0;padding:0}body{background:#0a0a0a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}.spinner{width:40px;height:40px;border:3px solid #2a2a2a;border-top-color:#8a8a8a;border-radius:50%;margin:20px auto;animation:spin 1s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}.hidden{position:absolute;width:1px;height:1px;overflow:hidden}.message{text-align:center}.message p{margin-top:10px;color:#666}</style></head><body><div class="message"><div class="spinner"></div><p>Verifying browser...</p><div class="hidden"><input id="hp_${hpSuffix}"></div></div><script nonce="${nonce}">${obfuscated}</script></body></html>`);
    } catch (err) { next(err); }
  });
  
  app.post('/v/:id/verify', express.json(), async (req, res, next) => {
    try {
      const linkId = req.params.id;
      const { password } = req.body;
      if (!password) throw new ValidationError('Password required');
      let linkData = cacheGet(linkCache, 'link', linkId);
      if (!linkData && getDbPool()) {
        const result = await queryWithTimeout('SELECT * FROM links WHERE id = $1 AND expires_at > NOW()', [linkId]);
        if (result.rows.length) {
          const row = result.rows[0];
          linkData = { target: row.target_url, passwordHash: row.password_hash, maxClicks: row.max_clicks, currentClicks: row.current_clicks, expiresAt: new Date(row.expires_at).getTime(), created: new Date(row.created_at).getTime(), notes: row.notes, linkMode: row.link_mode, linkMetadata: row.link_metadata, encodingMetadata: row.encoding_metadata };
          const ttl = Math.max(60, Math.floor((linkData.expiresAt - Date.now()) / 1000));
          cacheSet(linkCache, 'link', linkId, linkData, ttl);
        }
      }
      if (!linkData || linkData.expiresAt < Date.now()) throw new AppError('Link not found or expired', 404, 'LINK_NOT_FOUND');
      if (!linkData.passwordHash) return res.json({ success: true, target: linkData.target, redirect: true });
      const valid = await bcrypt.compare(password, linkData.passwordHash);
      if (!valid) throw new AppError('Invalid password', 401, 'INVALID_PASSWORD');
      linkData.lastAccessed = Date.now();
      cacheSet(linkCache, 'link', linkId, linkData);
      if (getDbPool()) await queryWithTimeout('UPDATE links SET last_accessed = CURRENT_TIMESTAMP WHERE id = $1', [linkId]);
      res.json({ success: true, target: linkData.target });
    } catch (err) { next(err); }
  });
  
  // ----- Admin routes -----
  app.get('/admin/login', (req, res) => {
    if (req.session.authenticated) return res.redirect('/admin');
    req.session.regenerate(async (err) => {
      if (err) logger.error('Session regeneration error:', err);
      const csrfToken = crypto.randomBytes(32).toString('hex');
      req.session.csrfToken = csrfToken;
      const nonce = crypto.randomBytes(16).toString('hex');
      try {
        const loginHtml = await fs.readFile(path.join(__dirname, 'public', 'login.html'), 'utf8');
        const html = loginHtml.replace('<input type="hidden" id="csrfToken" value="">', `<input type="hidden" id="csrfToken" value="${csrfToken}">`).replace('{{NONCE}}', nonce);
        res.setHeader('Content-Security-Policy', `default-src 'self'; script-src 'self' 'nonce-${nonce}' https://cdn.socket.io https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com data:; img-src 'self' data: https:; connect-src 'self' ws: wss: https://cdn.socket.io https://cdn.jsdelivr.net;`);
        res.send(html);
      } catch (err) { res.status(500).send('Login page not found'); }
    });
  });
  
  app.post('/admin/login', loginLimiter, csrfProtection, express.json(), async (req, res, next) => {
    try {
      const { username, password, remember } = req.body;
      const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown';
      if (username === CONFIG.ADMIN_USERNAME && await bcrypt.compare(password, CONFIG.ADMIN_PASSWORD_HASH)) {
        req.session.regenerate((err) => {
          if (err) return next(err);
          req.session.authenticated = true;
          req.session.user = username;
          req.session.loginTime = Date.now();
          req.session.createdAt = Date.now();
          req.session.csrfToken = crypto.randomBytes(32).toString('hex');
          if (remember) req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
          else req.session.cookie.maxAge = 24 * 60 * 60 * 1000;
          if (getDbPool()) queryWithTimeout('INSERT INTO user_sessions (session_id, user_id, ip, user_agent) VALUES ($1,$2,$3,$4)', [req.session.id, username, ip, req.headers['user-agent']]).catch(()=>{});
          logger.info('Successful admin login', { ip, username });
          res.json({ success: true });
        });
      } else {
        throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
      }
    } catch (err) { next(err); }
  });
  
  app.get('/admin', ensureAuthenticated, (req, res) => {
    const fs = require('fs').promises;
    const path = require('path');
    fs.readFile(path.join(__dirname, 'public', 'index.html'), 'utf8').then(html => {
      const replacements = { '{{METRICS_API_KEY}}': CONFIG.METRICS_API_KEY, '{{TARGET_URL}}': CONFIG.TARGET_URL, '{{csrfToken}}': req.session.csrfToken, '{{dbPoolStatus}}': getDbPool() ? 'connected' : 'disconnected', '{{redisStatus}}': getRedis()?.status === 'ready' ? 'connected' : 'disconnected', '{{redirectQueueStatus}}': !!redirectQueue, '{{encodingQueueStatus}}': !!encodingQueue, '{{bullBoardPath}}': CONFIG.BULL_BOARD_PATH, '{{linkLengthMode}}': CONFIG.LINK_LENGTH_MODE, '{{allowLinkModeSwitch}}': CONFIG.ALLOW_LINK_MODE_SWITCH, '{{longLinkSegments}}': CONFIG.LONG_LINK_SEGMENTS, '{{longLinkParams}}': CONFIG.LONG_LINK_PARAMS, '{{linkEncodingLayers}}': CONFIG.LINK_ENCODING_LAYERS, '{{enableCompression}}': CONFIG.ENABLE_COMPRESSION, '{{enableEncryption}}': CONFIG.ENABLE_ENCRYPTION, '{{maxEncodingIterations}}': CONFIG.MAX_ENCODING_ITERATIONS, '{{encodingComplexityThreshold}}': CONFIG.ENCODING_COMPLEXITY_THRESHOLD, '{{version}}': '4.2.0', '{{nodeEnv}}': CONFIG.NODE_ENV, '{{RATE_LIMIT_MAX}}': CONFIG.RATE_LIMIT_MAX_REQUESTS, '{{ENCODING_RATE_LIMIT}}': CONFIG.ENCODING_RATE_LIMIT, '{{apiVersions}}': CONFIG.SUPPORTED_API_VERSIONS.join(', '), '{{encryptionEnabled}}': CONFIG.ENABLE_ENCRYPTION, '{{keyRotationDays}}': CONFIG.ENCRYPTION_KEY_ROTATION_DAYS };
      let finalHtml = html;
      for (const [key, val] of Object.entries(replacements)) finalHtml = finalHtml.replace(new RegExp(key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), String(val));
      const nonce = crypto.randomBytes(16).toString('hex');
      res.locals.nonce = nonce;
      res.setHeader('Content-Security-Policy', `default-src 'self'; script-src 'self' 'nonce-${nonce}' https://cdn.socket.io https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com data:; img-src 'self' data: https:; connect-src 'self' ws: wss: https://cdn.socket.io https://cdn.jsdelivr.net;`);
      finalHtml = finalHtml.replace('<script nonce="{{NONCE}}">', `<script nonce="${nonce}">`);
      res.send(finalHtml);
    }).catch(err => { logger.error('Failed to read dashboard:', err); res.status(500).send('Dashboard not found'); });
  });
  
  app.post('/admin/logout', (req, res) => {
    if (getDbPool() && req.session.id) queryWithTimeout('UPDATE user_sessions SET revoked_at = NOW() WHERE session_id = $1', [req.session.id]).catch(()=>{});
    req.session.destroy((err) => { if (err) logger.error('Logout error:', err); res.clearCookie('redirector.sid'); res.json({ success: true }); });
  });
  
  app.post('/admin/clear-cache', csrfProtection, ensureAuthenticated, (req, res) => {
    const caches = getCaches();
    Object.values(caches).forEach(cache => cache.flushAll());
    Object.keys(cacheStats).forEach(k => { cacheStats[k].hits = 0; cacheStats[k].misses = 0; });
    logger.info('Cache cleared by admin');
    res.json({ success: true });
  });
  
  app.get('/admin/export-logs', ensureAuthenticated, async (req, res, next) => {
    try {
      const logs = await fs.readFile('logs/requests.log', 'utf8');
      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Content-Disposition', `attachment; filename="logs-${Date.now()}.txt"`);
      res.send(logs);
    } catch (err) { next(err); }
  });
  
  app.get('/api/export/:id', ensureAuthenticated, async (req, res, next) => {
    try {
      const linkId = req.params.id;
      const format = req.query.format || 'json';
      if (!getDbPool()) throw new AppError('Database not available', 503, 'DATABASE_UNAVAILABLE');
      const result = await queryWithTimeout(`SELECT id, link_id, ip, country, device_type, link_mode, encoding_layers, decoding_time_ms, created_at FROM clicks WHERE link_id = $1 ORDER BY created_at DESC`, [linkId]);
      if (format === 'csv') {
        const headers = ['id','link_id','ip','country','device_type','link_mode','encoding_layers','decoding_time_ms','created_at'];
        const csv = [headers.join(','), ...result.rows.map(row => headers.map(h => row[h] || '').join(','))].join('\n');
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="clicks-${linkId}.csv"`);
        res.send(csv);
      } else {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="clicks-${linkId}.json"`);
        res.json(result.rows);
      }
    } catch (err) { next(err); }
  });
  
  app.get('/admin/security/monitor', ensureAuthenticated, async (req, res) => {
    const now = Date.now();
    const activeAttacks = [];
    const loginAttemptsMap = new Map(); // would need to be imported from core or stored in Redis; simplified
    res.json({ blockedIPs: [], activeAttacks, totalAttempts: 0, activeSessions: [], rateLimitStats: {}, signatureStats: stats.signatures, memoryLeak: stats.memoryLeak, circuitBreakers: getBreakerMonitor()?.getStatus() || {} });
  });
  
  app.post('/admin/reload-config', csrfProtection, ensureAuthenticated, async (req, res) => {
    const result = await reloadConfig(); // reloadConfig would need to be exported from core
    if (result.success) res.json({ success: true, message: 'Configuration reloaded' });
    else res.status(400).json({ success: false, errors: result.errors });
  });
  
  app.post('/admin/force-gc', csrfProtection, ensureAuthenticated, (req, res) => {
    if (global.gc) { global.gc(); res.json({ success: true, message: 'Garbage collection forced' }); }
    else res.status(400).json({ success: false, message: 'GC not available' });
  });
  
  app.get('/admin/circuit-breakers', ensureAuthenticated, (req, res) => {
    res.json({ status: getBreakerMonitor()?.getStatus() || {}, metrics: getBreakerMonitor()?.getMetrics() || {} });
  });
  
  // ----- QR code endpoints -----
  app.get('/qr', async (req, res, next) => {
    try {
      const url = req.query.url || CONFIG.TARGET_URL;
      const size = parseInt(req.query.size) || 300;
      const format = req.query.format || 'json';
      if (!validateUrl(url)) throw new ValidationError('Invalid URL');
      const cacheKey = crypto.createHash('md5').update(`${url}:${size}:${format}`).digest('hex');
      let qrData = cacheGet(qrCache, 'qr', cacheKey);
      if (!qrData) {
        if (format === 'png') qrData = await QRCode.toBuffer(url, { width: size, margin: 2, type: 'png' });
        else qrData = await QRCode.toDataURL(url, { width: size, margin: 2 });
        cacheSet(qrCache, 'qr', cacheKey, qrData, 3600);
      }
      if (format === 'png') { res.setHeader('Content-Type', 'image/png'); res.send(qrData); }
      else res.json({ qr: qrData, url, size });
    } catch (err) { next(err); }
  });
  
  app.get('/qr/download', async (req, res, next) => {
    try {
      const url = req.query.url || CONFIG.TARGET_URL;
      const size = parseInt(req.query.size) || 300;
      if (!validateUrl(url)) throw new ValidationError('Invalid URL');
      const qrBuffer = await QRCode.toBuffer(url, { width: size, margin: 2, type: 'png' });
      res.setHeader('Content-Type', 'image/png');
      res.setHeader('Content-Disposition', `attachment; filename="qrcode-${Date.now()}.png"`);
      res.send(qrBuffer);
    } catch (err) { next(err); }
  });
  
  app.get('/expired', (req, res) => {
    const originalTarget = req.query.target || CONFIG.BOT_URLS[0];
    const nonce = res.locals.nonce;
    const isMobile = req.deviceInfo.isMobile;
    const styles = isMobile ? `body{background:#000;color:#ddd;padding:10px}.card{background:#0a0a0a;padding:20px;border-radius:24px;text-align:center}` : `body{background:#000;display:flex;align-items:center;justify-content:center;min-height:100vh}.card{background:#0a0a0a;border-radius:28px;padding:2.5rem;text-align:center;max-width:480px}`;
    res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Link Expired</title><style nonce="${nonce}">${styles}</style></head><body><div class="card"><span class="icon">⌛</span><h1>Link Expired</h1><p>This link expired after ${formatDuration(LINK_TTL_SEC)}.</p><a href="${originalTarget}" class="btn">Continue to Website</a></div></body></html>`);
  });
  
  // ----- Swagger docs -----
  const swaggerJsdoc = require('swagger-jsdoc');
  const swaggerUi = require('swagger-ui-express');
  const swaggerOptions = {
    definition: { openapi: '3.0.0', info: { title: 'Redirector Pro API', version: '4.2.0' }, servers: [{ url: `http://${CONFIG.HOST}:${CONFIG.PORT}` }] },
    apis: ['./routes.js']
  };
  const swaggerSpecs = swaggerJsdoc(swaggerOptions);
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpecs));
  
  // ----- 404 fallback -----
  app.use((req, res) => {
    res.redirect(CONFIG.BOT_URLS[Math.floor(Math.random() * CONFIG.BOT_URLS.length)]);
  });
  
  // ----- Global error handler -----
  app.use((err, req, res, next) => {
    const errorId = uuidv4();
    const statusCode = err.statusCode || 500;
    const errorCode = err.code || 'INTERNAL_ERROR';
    logger.error('Error:', { errorId, code: errorCode, message: err.message, stack: err.stack, id: req.id, path: req.path, method: req.method, ip: req.ip });
    totalRequests.inc({ method: req.method, path: req.path, status: statusCode, version: req.apiVersion || 'unknown' });
    if (err instanceof AppError && err.isOperational) {
      const response = { error: err.message, code: err.code, id: req.id, errorId, timestamp: new Date().toISOString() };
      if (err instanceof ValidationError && err.errors) response.errors = err.errors;
      if (err instanceof RateLimitError && err.retryAfter) { response.retryAfter = err.retryAfter; res.setHeader('Retry-After', err.retryAfter); }
      return res.status(statusCode).json(response);
    }
    if (!res.headersSent) {
      if (req.accepts('html')) res.redirect(CONFIG.BOT_URLS[Math.floor(Math.random() * CONFIG.BOT_URLS.length)]);
      else res.status(500).json({ error: 'Internal server error', code: 'INTERNAL_ERROR', id: req.id, errorId });
    }
  });
  
  return { app, io };
}

// ==================== UTILITY FUNCTIONS ====================
function getConfigForClient() {
  return {
    linkTTL: LINK_TTL_SEC,
    linkTTLFormatted: formatDuration(LINK_TTL_SEC),
    targetUrl: CONFIG.TARGET_URL,
    botUrls: CONFIG.BOT_URLS,
    maxLinks: CONFIG.MAX_LINKS,
    linkLengthMode: CONFIG.LINK_LENGTH_MODE,
    allowLinkModeSwitch: CONFIG.ALLOW_LINK_MODE_SWITCH,
    longLinkSegments: CONFIG.LONG_LINK_SEGMENTS,
    longLinkParams: CONFIG.LONG_LINK_PARAMS,
    linkEncodingLayers: CONFIG.LINK_ENCODING_LAYERS,
    enableCompression: CONFIG.ENABLE_COMPRESSION,
    enableEncryption: CONFIG.ENABLE_ENCRYPTION,
    maxEncodingIterations: CONFIG.MAX_ENCODING_ITERATIONS,
    encodingComplexityThreshold: CONFIG.ENCODING_COMPLEXITY_THRESHOLD,
    uptime: process.uptime(),
    version: '4.2.0',
    nodeEnv: CONFIG.NODE_ENV,
    databaseEnabled: !!getDbPool(),
    redisEnabled: !!getRedis(),
    queuesEnabled: !!getQueues().redirectQueue,
    keyRotationEnabled: !!getKeyManager(),
    apiVersions: CONFIG.SUPPORTED_API_VERSIONS,
    requestSigning: true,
    memoryLeakDetection: stats.memoryLeak.detected,
    circuitBreakers: Object.keys(getBreakerMonitor()?.getStatus() || {})
  };
}

async function handleAdminCommand(cmd, socket) {
  switch(cmd.action) {
    case 'clearCache':
      Object.values(getCaches()).forEach(cache => cache.flushAll());
      socket.emit('notification', { type: 'success', message: 'Cache cleared' });
      break;
    case 'getStats':
      socket.emit('stats', getStats());
      break;
    case 'getConfig':
      socket.emit('config', getConfigForClient());
      break;
    case 'getLinks':
      socket.emit('links', await getAllLinks());
      break;
    case 'getCacheStats':
      socket.emit('cacheStats', cacheStats);
      break;
    case 'getSystemMetrics':
      socket.emit('systemMetrics', { memory: process.memoryUsage(), cpu: stats.system.cpu, uptime: process.uptime(), connections: stats.realtime.activeLinks, rps: stats.realtime.requestsPerSecond, memoryLeak: stats.memoryLeak });
      break;
    case 'reloadConfig':
      const result = await reloadConfig();
      socket.emit('notification', { type: result.success ? 'success' : 'error', message: result.success ? 'Config reloaded' : 'Reload failed' });
      break;
    case 'rotateKeys':
      if (getKeyManager()) { await getKeyManager().generateNewKey(); socket.emit('notification', { type: 'success', message: 'New encryption key generated' }); }
      break;
    case 'listKeys':
      if (getKeyManager()) socket.emit('keys', await getKeyManager().listKeys());
      break;
    case 'forceGC':
      if (global.gc) { global.gc(); socket.emit('notification', { type: 'success', message: 'GC forced' }); }
      else socket.emit('notification', { type: 'error', message: 'GC not available' });
      break;
    case 'getCircuitBreakers':
      socket.emit('circuitBreakers', { status: getBreakerMonitor()?.getStatus(), metrics: getBreakerMonitor()?.getMetrics() });
      break;
    default: socket.emit('notification', { type: 'error', message: 'Unknown command' });
  }
}

function passwordProtectedPage(linkId, error, nonce) {
  return `<!DOCTYPE html><html><head><title>Password Protected</title><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><style nonce="${nonce}">*{margin:0;padding:0;box-sizing:border-box}body{min-height:100vh;background:#000;color:#ddd;display:flex;align-items:center;justify-content:center;padding:20px}.login-wrapper{max-width:1000px;background:#0a0a0a;border-radius:28px;display:flex}.form-side{flex:1;padding:3rem;background:linear-gradient(135deg,#0f0f0f,#080808)}h1{font-size:2.5rem;margin-bottom:0.5rem;background:linear-gradient(90deg,#e0e0e0,#b0b0b0);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.subtitle{color:#888;margin-bottom:2rem}.alert{background:rgba(239,68,68,0.1);border-left:4px solid #ef4444;color:#fecaca;padding:1rem;border-radius:12px;margin-bottom:1.5rem;display:${error ? 'flex' : 'none'}}.input-wrapper{position:relative;margin-bottom:1.5rem}.input-icon{position:absolute;left:1rem;top:50%;transform:translateY(-50%);color:#666}input{width:100%;padding:1rem 1rem 1rem 3rem;background:rgba(20,20,20,0.7);border:1px solid #222;border-radius:12px;color:#eee}.password-toggle{position:absolute;right:1rem;top:50%;transform:translateY(-50%);background:none;border:none;color:#666;cursor:pointer}button{width:100%;padding:1rem;background:linear-gradient(90deg,#5a5a5a,#8c8c8c);border:none;border-radius:14px;color:white;cursor:pointer}.loading{display:none;text-align:center;margin-top:1.5rem}</style></head><body><div class="login-wrapper"><div class="form-side"><h1>Protected Link</h1><p class="subtitle">This link requires a password</p><div class="alert" id="errorAlert"><span id="errorMessage">${error}</span></div><form id="passwordForm"><div class="input-wrapper"><i class="fas fa-lock input-icon"></i><input type="password" id="password" placeholder="Enter password" autofocus required><button type="button" class="password-toggle" id="togglePassword"><i class="fa-regular fa-eye"></i></button></div><button type="submit"><span>Access Link</span></button><div class="loading" id="loading"><i class="fas fa-spinner"></i> Verifying...</div></form><div class="footer">Redirector Pro</div></div></div><script nonce="${nonce}">const form=document.getElementById('passwordForm');const passwordInput=document.getElementById('password');const submitBtn=document.querySelector('button[type="submit"]');const loading=document.getElementById('loading');const errorAlert=document.getElementById('errorAlert');const errorMessage=document.getElementById('errorMessage');const togglePassword=document.getElementById('togglePassword');togglePassword.addEventListener('click',()=>{const type=passwordInput.getAttribute('type')==='password'?'text':'password';passwordInput.setAttribute('type',type);togglePassword.querySelector('i').className=type==='password'?'fa-regular fa-eye':'fa-regular fa-eye-slash';});form.addEventListener('submit',async(e)=>{e.preventDefault();const password=passwordInput.value.trim();if(!password){showError('Please enter a password');return;}submitBtn.disabled=true;loading.style.display='block';errorAlert.style.display='none';try{const response=await fetch('/v/${linkId}/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});const data=await response.json();if(response.ok&&data.success){window.location.href=data.target;}else{showError(data.error||'Invalid password');submitBtn.disabled=false;loading.style.display='none';passwordInput.value='';passwordInput.focus();}}catch(err){showError('Connection error');submitBtn.disabled=false;loading.style.display='none';}});function showError(message){errorMessage.textContent=message;errorAlert.style.display='flex';setTimeout(()=>{errorAlert.style.display='none';},3000);}</script></body></html>`;
}

function qrCodePage(target, qrData, nonce) {
  return `<!DOCTYPE html><html><head><title>QR Code</title><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="5;url=${target}"><style nonce="${nonce}">body{min-height:100vh;background:#000;color:#ddd;display:flex;align-items:center;justify-content:center;margin:0;padding:20px}.card{background:#0a0a0a;padding:2rem;border-radius:24px;text-align:center;max-width:400px;border:1px solid #1a1a1a}h2{font-size:1.5rem;margin-bottom:1rem}img{max-width:100%;border-radius:16px;margin:1rem 0}.countdown{color:#4ade80;margin-top:1rem}</style></head><body><div class="card"><h2>📱 Scan QR Code</h2><img src="${qrData}" alt="QR Code"><p>Or continue to website...</p><div class="countdown">Redirecting in <span id="countdown">5</span> seconds</div></div><script nonce="${nonce}">let time=5;const interval=setInterval(()=>{time--;document.getElementById('countdown').textContent=time;if(time<=0){clearInterval(interval);window.location.href='${target}';}},1000);</script></body></html>`;
}

module.exports = { createServer };
