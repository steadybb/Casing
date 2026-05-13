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
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const JavaScriptObfuscator = require('javascript-obfuscator');
const { v4: uuidv4 } = require('uuid');
const { createBullBoard } = require('@bull-board/api');
const { BullAdapter } = require('@bull-board/api/bullAdapter');
const { ExpressAdapter } = require('@bull-board/express');

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
  cacheStats,
  AppError,
  ValidationError,
  DatabaseError,
  parseTTL,
  formatDuration,
  validateUrl,
  sanitizeLogEntry,
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
  httpRequestDurationMicroseconds,
  totalRequests,
  botBlocks,
  linkGenerations,
  linkModeCounter,
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

// ==================== CONSTANTS ====================
const LINK_TTL_SEC = parseTTL(CONFIG.LINK_TTL);
const MAX_IP_REQUESTS = 5;
const MAX_LONG_LINK_REQUESTS = 3;
const PASSWORD_PROTECTED_TIMEOUT = 1200; // 1.2 seconds
const NONCE_EXPIRY_MS = 3600000; // 1 hour

// ==================== RATE LIMITERS ====================

// Main rate limiter with device-aware logic
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
  skipFailedRequests: false,
  keyGenerator: (req) =>
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown',
  handler: (req, res) => {
    logger.warn('Rate limit exceeded', {
      ip: req.ip,
      endpoint: req.path,
      device: req.deviceInfo?.type
    });
    if (botBlocks && typeof botBlocks.inc === 'function') {
      botBlocks.inc({ reason: 'rate_limit' });
    } else {
      stats.botBlocks++;
    }
    res.redirect(CONFIG.BOT_URLS[crypto.randomInt(0, CONFIG.BOT_URLS.length)]);
  }
});

// Encoding rate limiter
const encodingLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: CONFIG.ENCODING_RATE_LIMIT,
  keyGenerator: (req) => req.session?.user || req.ip || 'unknown',
  handler: (req, res) => {
    logger.warn('Encoding rate limit exceeded', { ip: req.ip, user: req.session?.user });
    res.status(429).json({
      error: 'Too many encoding requests. Please slow down.',
      code: 'RATE_LIMIT_ENCODING',
      retryAfter: 60
    });
  }
});

// Login rate limiter
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: CONFIG.LOGIN_ATTEMPTS_MAX,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => req.ip,
  handler: (req, res) => {
    logger.warn('Login rate limit exceeded', { ip: req.ip });
    res.status(429).json({
      error: 'Too many login attempts. Please try again later.',
      code: 'RATE_LIMIT_LOGIN',
      retryAfter: 900
    });
  }
});

// Speed limiter (progressive delay)
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 50,
  delayMs: (hits) => Math.min(hits * 100, 5000),
  skip: (req) => req.deviceInfo?.isBot || req.path.startsWith('/api')
});

// ==================== CSRF PROTECTION ====================
const csrfProtection = (req, res, next) => {
  // Skip CSRF for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  const token =
    req.body._csrf ||
    req.query._csrf ||
    req.headers['csrf-token'] ||
    req.headers['xsrf-token'] ||
    req.headers['x-csrf-token'] ||
    req.headers['x-xsrf-token'] ||
    req.cookies['XSRF-TOKEN'];

  if (!token || !req.session?.csrfToken || token !== req.session.csrfToken) {
    logger.warn('CSRF validation failed', {
      id: req.id,
      ip: req.ip,
      path: req.path,
      method: req.method
    });

    if (req.path.startsWith('/api/') || req.xhr) {
      return res.status(403).json({
        error: 'Invalid CSRF token',
        code: 'CSRF_VALIDATION_FAILED',
        id: req.id
      });
    }
    return res.redirect('/admin/login?error=invalid_csrf');
  }

  next();
};

// ==================== AUTH MIDDLEWARE ====================
const ensureAuthenticated = (req, res, next) => {
  if (!req.session?.authenticated) {
    return res.redirect('/admin/login');
  }
  next();
};

// Session absolute timeout
const sessionAbsoluteTimeout = (req, res, next) => {
  if (req.session?.createdAt) {
    const age = Date.now() - req.session.createdAt;
    if (age > CONFIG.SESSION_ABSOLUTE_TIMEOUT * 1000) {
      return req.session.destroy((err) => {
        if (err) logger.error('Session destruction error:', sanitizeLogEntry(err.message));
        res.redirect('/admin/login?expired=true');
      });
    }
  } else if (req.session) {
    req.session.createdAt = Date.now();
  }
  next();
};

// Request timeout middleware
const requestTimeout = (timeout = CONFIG.REQUEST_TIMEOUT) => (req, res, next) => {
  const timer = setTimeout(() => {
    logger.error('Request timeout', {
      id: req.id,
      path: req.path,
      method: req.method,
      timeout,
      ip: req.ip
    });

    if (!res.headersSent) {
      res.status(504).json({
        error: 'Request timeout',
        code: 'REQUEST_TIMEOUT',
        id: req.id
      });
    }
  }, timeout);

  res.on('finish', () => clearTimeout(timer));
  res.on('close', () => clearTimeout(timer));
  next();
};

// ==================== REQUEST VALIDATION MIDDLEWARE ====================

// Validate request body size (prevent payload bombs)
const validateRequestSize = express.json({ limit: CONFIG.MAX_REQUEST_SIZE });
const validateRequestUrlEncoded = express.urlencoded({
  extended: true,
  limit: CONFIG.MAX_REQUEST_SIZE
});

// ==================== CREATE EXPRESS APP & SOCKET.IO ====================
function createServer(app, server) {
  // ----- Trust proxy -----
  app.set('trust proxy', CONFIG.TRUST_PROXY);

  // ----- Static files (with caching) -----
  app.use(
    express.static('public', {
      maxAge: '7d',
      etag: true,
      lastModified: true,
      immutable: true,
      index: false
    })
  );

  // ----- Standard middleware -----
  app.use(compression({ level: 6, threshold: 1024 }));

  // Morgan logging with stream
  const morganStream = {
    write: (message) => {
      const sanitized = sanitizeLogEntry(message.trim());
      logger.info('HTTP', { message: sanitized });
    }
  };
  app.use(morgan(CONFIG.LOG_FORMAT === 'json' ? 'combined' : 'dev', { stream: morganStream }));

  // Body parsers with size limits
  app.use(validateRequestSize);
  app.use(validateRequestUrlEncoded);

  // Cookie parser
  app.use(cookieParser(CONFIG.SESSION_SECRET));

  // CORS
  app.use(
    cors({
      origin: CONFIG.CORS_ORIGIN === '*' ? '*' : CONFIG.CORS_ORIGIN.split(',').map(o => o.trim()),
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-CSRF-Token',
        'X-Request-ID',
        'X-Signature',
        'X-Timestamp',
        'X-Nonce',
        'X-API-Version'
      ]
    })
  );

  // XSS protection
  app.use(xss());

  // HPP (HTTP Parameter Pollution protection)
  app.use(hpp());

  // ----- Helmet security -----
  const helmetConfig = {
    contentSecurityPolicy: CONFIG.CSP_ENABLED
      ? {
          directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
              "'self'",
              'https://cdn.socket.io',
              'https://cdn.jsdelivr.net',
              'https://cdnjs.cloudflare.com'
            ],
            styleSrc: [
              "'self'",
              "'unsafe-inline'",
              'https://cdn.jsdelivr.net',
              'https://cdnjs.cloudflare.com'
            ],
            fontSrc: ["'self'", 'https://cdnjs.cloudflare.com', 'data:'],
            imgSrc: ["'self'", 'data:', 'https:', 'http:'],
            connectSrc: [
              "'self'",
              'ws:',
              'wss:',
              'https://cdn.socket.io',
              'https://cdn.jsdelivr.net',
              'https://ipinfo.io'
            ],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"]
          }
        }
      : false,
    hsts: CONFIG.HSTS_ENABLED
      ? {
          maxAge: 31536000,
          includeSubDomains: true,
          preload: true
        }
      : false,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    noSniff: true,
    xssFilter: true,
    hidePoweredBy: true,
    frameguard: { action: 'deny' },
    ieNoOpen: true,
    dnsPrefetchControl: { allow: false }
  };
  app.use(helmet(helmetConfig));

  // ----- Session configuration -----
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
      sameSite: 'lax',
      domain: undefined // Use default domain
    },
    rolling: true,
    unset: 'destroy',
    genid: () => uuidv4()
  };
  app.use(session(sessionConfig));
  app.use(sessionAbsoluteTimeout);

  // ----- Request context -----
  app.use((req, res, next) => {
    req.id = req.headers['x-request-id'] || uuidv4();
    res.setHeader('X-Request-ID', req.id);
    res.setHeader('X-Powered-By', 'Redirector-Pro');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    res.setHeader('X-API-Versions', CONFIG.SUPPORTED_API_VERSIONS.join(', '));
    next();
  });

  // ----- Device detection -----
  app.use((req, res, next) => {
    req.deviceInfo = getDeviceInfo(req);
    res.locals.nonce = crypto.randomBytes(16).toString('hex');
    res.locals.startTime = Date.now();
    res.locals.deviceInfo = req.deviceInfo;
    res.setHeader('X-Device-Type', req.deviceInfo.type);
    next();
  });

  // ----- Response time metrics -----
  app.use(
    responseTime((req, res, time) => {
      if (req.route?.path) {
        const route = req.route.path;
        const version = req.apiVersion || 'unknown';
        httpRequestDurationMicroseconds
          .labels(req.method, route, res.statusCode, version)
          .observe(time);
      }

      totalRequests.inc({
        method: req.method,
        path: req.path,
        status: res.statusCode,
        version: req.apiVersion || 'unknown'
      });

      stats.totalRequests++;
      stats.performance.totalResponseTime += time;
      stats.performance.avgResponseTime = stats.performance.totalResponseTime / stats.totalRequests;

      // Keep response times history bounded
      stats.performance.responseTimes.push(time);
      if (stats.performance.responseTimes.length > CONFIG.MAX_RESPONSE_TIMES_HISTORY) {
        stats.performance.responseTimes = stats.performance.responseTimes.slice(
          -CONFIG.MAX_RESPONSE_TIMES_HISTORY
        );
      }

      if (req.apiVersion) {
        stats.apiVersions[req.apiVersion] = (stats.apiVersions[req.apiVersion] || 0) + 1;
      }
    })
  );

  // ----- Rate limiting & timeout -----
  app.use(speedLimiter);
  app.use(requestTimeout(CONFIG.REQUEST_TIMEOUT));

  // ----- CSRF token generation & management -----
  app.use((req, res, next) => {
    if (!req.session?.csrfToken) {
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    res.cookie('XSRF-TOKEN', req.session.csrfToken, {
      secure: CONFIG.NODE_ENV === 'production' && CONFIG.HTTPS_ENABLED,
      httpOnly: false,
      sameSite: 'lax',
      maxAge: NONCE_EXPIRY_MS
    });
    res.locals.csrfToken = req.session.csrfToken;
    res.setHeader('X-CSRF-Token', req.session.csrfToken);
    next();
  });

  // ----- Request signing (v2) -----
  app.use(requestSigner.signRequest.bind(requestSigner));
  app.use(
    '/api/v2/*',
    requestSigner.requireSignature(['/api/v2/generate', '/api/v2/bulk'])
  );

  // ----- Socket.IO -----
  const io = new Server(server, {
    cors: {
      origin: CONFIG.CORS_ORIGIN === '*' ? '*' : CONFIG.CORS_ORIGIN.split(','),
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE']
    },
    pingTimeout: 60000,
    pingInterval: 25000,
    transports: ['websocket', 'polling'],
    maxHttpBufferSize: 1e6,
    connectTimeout: 45000,
    path: '/socket.io/',
    serveClient: false
  });

  // Socket.IO authentication middleware
  io.of('/admin').use((socket, next) => {
    const token = socket.handshake.auth.token;
    const sessionId = socket.handshake.auth.sessionId;

    if (token === CONFIG.METRICS_API_KEY) {
      return next();
    }

    if (sessionId && getSessionStore()) {
      getSessionStore().get(sessionId, (err, sess) => {
        if (err || !sess?.authenticated) {
          logger.warn('Socket.IO authentication failed', {
            socketId: socket.id,
            sessionId,
            error: err?.message
          });
          return next(new Error('Authentication failed'));
        }
        socket.session = sess;
        next();
      });
    } else {
      next(new Error('Missing authentication'));
    }
  });

  // Socket.IO connection handler
  io.of('/admin').on('connection', (socket) => {
    logger.info('Admin socket connected', { socketId: socket.id });

    socket.emit('stats', getStats());
    socket.emit('config', getConfigForClient());

    getAllLinks()
      .then((links) => socket.emit('links', links))
      .catch((err) =>
        logger.error('Failed to fetch links:', sanitizeLogEntry(err.message))
      );

    socket.on('disconnect', () => {
      logger.info('Admin socket disconnected', { socketId: socket.id });
    });

    socket.on('command', async (cmd) => {
      try {
        await handleAdminCommand(cmd, socket);
      } catch (err) {
        logger.error('Admin command error:', sanitizeLogEntry(err.message));
        socket.emit('notification', {
          type: 'error',
          message: 'Command failed'
        });
      }
    });
  });

  // ----- Bull Board (queue monitoring) -----
  if (CONFIG.BULL_BOARD_ENABLED && redirectQueue) {
    const serverAdapter = new ExpressAdapter();
    serverAdapter.setBasePath(CONFIG.BULL_BOARD_PATH);
    createBullBoard({
      queues: [
        new BullAdapter(redirectQueue),
        new BullAdapter(emailQueue),
        new BullAdapter(analyticsQueue),
        new BullAdapter(encodingQueue)
      ],
      serverAdapter
    });
    app.use(CONFIG.BULL_BOARD_PATH, ensureAuthenticated, serverAdapter.getRouter());
  }

  // ==================== ROUTES ====================

  // ----- Health & Metrics -----
  app.get(['/ping', '/health', '/healthz', '/status'], (req, res) => {
    const dbPool = getDbPool();
    const redisClient = getRedis();
    const queues = getQueues();

    res.json({
      status: 'healthy',
      time: Date.now(),
      uptime: process.uptime(),
      id: req.id,
      version: '4.3.0',
      memory: process.memoryUsage(),
      stats: {
        totalRequests: stats.totalRequests,
        activeLinks: linkCache.size,
        botBlocks: stats.botBlocks,
        linkModes: stats.linkModes,
        encodingStats: {
          avgLayers: stats.encodingStats.avgLayers,
          avgComplexity: stats.encodingStats.avgComplexity,
          totalEncoded: stats.encodingStats.totalEncoded
        },
        apiVersions: stats.apiVersions,
        memoryLeak: stats.memoryLeak.detected
      },
      services: {
        database: dbPool ? 'connected' : 'disabled',
        redis: redisClient?.status === 'ready' ? 'connected' : 'disabled',
        queues: {
          redirect: !!queues.redirectQueue,
          email: !!queues.emailQueue,
          analytics: !!queues.analyticsQueue,
          encoding: !!queues.encodingQueue
        },
        encryption: getKeyManager()?.initialized || false,
        circuitBreakers: Object.keys(getBreakerMonitor()?.getStatus() || {})
      }
    });
  });

  app.get('/metrics', async (req, res) => {
    const apiKey = req.headers['x-api-key'] || req.query.key;
    if (apiKey !== CONFIG.METRICS_API_KEY) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    try {
      const promClient = require('prom-client');
      res.set('Content-Type', promClient.register.contentType);
      const metrics = await promClient.register.metrics();
      res.send(metrics);
    } catch (err) {
      logger.error('Failed to generate metrics:', sanitizeLogEntry(err.message));
      res.status(500).json({ error: 'Failed to generate metrics' });
    }
  });

  // ----- API Versioning -----
  const v1Router = express.Router();
  const v2Router = express.Router();

  // ===== V1 ROUTES =====

  /**
   * Generate short or long redirect link
   * POST /api/v1/generate
   */
  v1Router.post('/generate', csrfProtection, encodingLimiter, async (req, res, next) => {
    try {
      const target = req.body.url || CONFIG.TARGET_URL;
      if (!validateUrl(target)) {
        throw new ValidationError('Invalid target URL');
      }

      const password = req.body.password;
      const maxClicks = req.body.maxClicks;
      const expiresIn = req.body.expiresIn ? parseTTL(req.body.expiresIn) : LINK_TTL_SEC;
      const notes = req.body.notes ? req.body.notes.substring(0, 500) : '';

      let linkMode = req.body.linkMode || CONFIG.LINK_LENGTH_MODE;
      if (linkMode === 'auto') {
        linkMode = target.length > 100 ? 'long' : 'short';
      }
      if (!CONFIG.ALLOW_LINK_MODE_SWITCH) {
        linkMode = CONFIG.LINK_LENGTH_MODE;
      }

      let generatedUrl,
        linkMetadata = {},
        cacheId,
        encodingMetadata = {};

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

      const passwordHash = password
        ? await bcrypt.hash(password, CONFIG.BCRYPT_ROUNDS)
        : null;

      const linkData = {
        target,
        created: Date.now(),
        expiresAt: Date.now() + expiresIn * 1000,
        passwordHash,
        maxClicks: maxClicks ? Math.min(parseInt(maxClicks, 10), 1000000) : null,
        currentClicks: 0,
        notes,
        linkMode,
        linkMetadata,
        encodingMetadata,
        metadata: {
          ...linkMetadata,
          userAgent: req.headers['user-agent']?.substring(0, 200),
          creator: req.session?.user || 'anonymous',
          ip: req.ip,
          apiVersion: 'v1'
        }
      };

      cacheSet(linkCache, 'link', cacheId, linkData, expiresIn);

      // Store in database if available
      if (getDbPool()) {
        try {
          await queryWithTimeout(
            `INSERT INTO links (id, target_url, created_at, expires_at, creator_ip, password_hash, max_clicks, current_clicks, link_mode, link_metadata, encoding_metadata, metadata, encoding_complexity, user_agent, api_version)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
            [
              cacheId,
              target,
              new Date(),
              new Date(Date.now() + expiresIn * 1000),
              req.ip,
              passwordHash,
              linkData.maxClicks,
              0,
              linkMode,
              JSON.stringify(linkMetadata),
              JSON.stringify(encodingMetadata),
              JSON.stringify(linkData.metadata),
              encodingMetadata.complexity || 0,
              req.headers['user-agent']?.substring(0, 200),
              'v1'
            ]
          );
        } catch (dbErr) {
          logger.error('Failed to store link in database:', sanitizeLogEntry(dbErr.message));
          // Continue - cache is still valid
        }
      }

      stats.generatedLinks++;
      linkGenerations.inc({ mode: linkMode, version: 'v1' });
      stats.linkModes[linkMode] = (stats.linkModes[linkMode] || 0) + 1;

      const linkLength = generatedUrl.length;
      stats.linkLengths.total += linkLength;
      stats.linkLengths.avg = stats.linkLengths.total / stats.generatedLinks;
      stats.linkLengths.min = Math.min(stats.linkLengths.min, linkLength);
      stats.linkLengths.max = Math.max(stats.linkLengths.max, linkLength);

      res.json({
        url: generatedUrl,
        mode: linkMode,
        expires: expiresIn,
        expires_human: formatDuration(expiresIn),
        id: cacheId,
        created: Date.now(),
        passwordProtected: !!password,
        maxClicks: linkData.maxClicks,
        notes,
        linkLength,
        metadata: linkMetadata,
        encodingDetails:
          linkMode === 'long'
            ? {
                layers: encodingMetadata.layers?.length,
                complexity: encodingMetadata.complexity,
                iterations: encodingMetadata.metadata?.iterations
              }
            : null,
        apiVersion: 'v1'
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * Get statistics for a link
   * GET /api/v1/stats/:id
   */
  v1Router.get('/stats/:id', async (req, res, next) => {
    try {
      const linkId = req.params.id;
      if (!linkId.match(/^[a-f0-9]{32}$/i)) {
        throw new ValidationError('Invalid link ID format');
      }

      const linkData = cacheGet(linkCache, 'link', linkId);
      let statsRes = {
        exists: !!linkData,
        created: linkData?.created,
        expiresAt: linkData?.expiresAt,
        target_url: linkData?.target,
        clicks: linkData?.currentClicks || 0,
        maxClicks: linkData?.maxClicks,
        passwordProtected: !!linkData?.passwordHash,
        notes: linkData?.notes || '',
        linkMode: linkData?.linkMode,
        linkLength: linkData?.linkMetadata?.length || 0,
        encodingLayers: linkData?.encodingMetadata?.layers?.length || 0,
        encodingComplexity: linkData?.encodingMetadata?.complexity || 0,
        uniqueVisitors: 0,
        countries: {},
        devices: {},
        recentClicks: []
      };

      if (getDbPool() && linkData) {
        try {
          const result = await queryWithTimeout(
            'SELECT COUNT(*) as total_clicks, COUNT(DISTINCT ip) as unique_visitors FROM clicks WHERE link_id = $1',
            [linkId]
          );
          const countryResult = await queryWithTimeout(
            'SELECT country, COUNT(*) as count FROM clicks WHERE link_id=$1 AND country IS NOT NULL GROUP BY country LIMIT 100',
            [linkId]
          );
          const recentResult = await queryWithTimeout(
            'SELECT ip, country, device_type, created_at FROM clicks WHERE link_id=$1 ORDER BY created_at DESC LIMIT 10',
            [linkId]
          );

          if (result.rows[0]) {
            statsRes = {
              ...statsRes,
              ...result.rows[0]
            };
          }
          if (countryResult.rows.length) {
            statsRes.countries = Object.fromEntries(
              countryResult.rows.map((r) => [r.country, parseInt(r.count, 10)])
            );
          }
          statsRes.recentClicks = recentResult.rows;
        } catch (dbErr) {
          logger.warn('Failed to fetch detailed stats:', sanitizeLogEntry(dbErr.message));
        }
      }

      res.json(statsRes);
    } catch (err) {
      next(err);
    }
  });

  // ===== V2 ROUTES =====

  /**
   * V2 generate with request signing and validation
   */
  v2Router.use(requestSigner.verifySignature.bind(requestSigner));

  v2Router.post('/generate', encodingLimiter, async (req, res, next) => {
    try {
      const validated = validator.validate('generateLink', req.body);
      const target = validated.url || CONFIG.TARGET_URL;

      if (!validateUrl(target)) {
        throw new ValidationError('Invalid target URL');
      }

      const password = validated.password;
      const maxClicks = validated.maxClicks;
      const expiresIn = validated.expiresIn
        ? parseTTL(validated.expiresIn)
        : LINK_TTL_SEC;
      const notes = validated.notes || '';

      let linkMode = validated.linkMode || CONFIG.LINK_LENGTH_MODE;
      if (linkMode === 'auto') {
        linkMode = target.length > 100 ? 'long' : 'short';
      }
      if (!CONFIG.ALLOW_LINK_MODE_SWITCH) {
        linkMode = CONFIG.LINK_LENGTH_MODE;
      }

      let generatedUrl,
        linkMetadata = {},
        cacheId,
        encodingMetadata = {};

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

      const passwordHash = password
        ? await bcrypt.hash(password, CONFIG.BCRYPT_ROUNDS)
        : null;

      const linkData = {
        target,
        created: Date.now(),
        expiresAt: Date.now() + expiresIn * 1000,
        passwordHash,
        maxClicks: maxClicks ? Math.min(parseInt(maxClicks, 10), 1000000) : null,
        currentClicks: 0,
        notes,
        linkMode,
        linkMetadata,
        encodingMetadata,
        metadata: {
          ...linkMetadata,
          userAgent: req.headers['user-agent']?.substring(0, 200),
          creator: req.session?.user || 'anonymous',
          ip: req.ip,
          apiVersion: 'v2',
          signature: req.signature?.signature
        }
      };

      cacheSet(linkCache, 'link', cacheId, linkData, expiresIn);

      // Store in database with transaction for v2
      if (getDbPool() && getTxManager()) {
        try {
          await getTxManager().retryTransaction(async (client) => {
            await client.query(
              `INSERT INTO links (id, target_url, created_at, expires_at, creator_ip, password_hash, max_clicks, current_clicks, link_mode, link_metadata, encoding_metadata, metadata, encoding_complexity, user_agent, api_version)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
              [
                cacheId,
                target,
                new Date(),
                new Date(Date.now() + expiresIn * 1000),
                req.ip,
                passwordHash,
                linkData.maxClicks,
                0,
                linkMode,
                JSON.stringify(linkMetadata),
                JSON.stringify(encodingMetadata),
                JSON.stringify(linkData.metadata),
                encodingMetadata.complexity || 0,
                req.headers['user-agent']?.substring(0, 200),
                'v2'
              ]
            );

            // Audit log
            await client.query(
              `INSERT INTO audit_logs (action, link_id, user_id, ip, metadata) VALUES ('CREATE_LINK', $1, $2, $3, $4)`,
              [
                cacheId,
                req.session?.user || 'anonymous',
                req.ip,
                JSON.stringify({ mode: linkMode, version: 'v2' })
              ]
            );
          });
        } catch (dbErr) {
          logger.error('Failed to store link:', sanitizeLogEntry(dbErr.message));
        }
      }

      stats.generatedLinks++;
      linkGenerations.inc({ mode: linkMode, version: 'v2' });
      stats.linkModes[linkMode] = (stats.linkModes[linkMode] || 0) + 1;

      const linkLength = generatedUrl.length;
      stats.linkLengths.total += linkLength;
      stats.linkLengths.avg = stats.linkLengths.total / stats.generatedLinks;
      stats.linkLengths.min = Math.min(stats.linkLengths.min, linkLength);
      stats.linkLengths.max = Math.max(stats.linkLengths.max, linkLength);

      res.status(201).json({
        success: true,
        data: {
          url: generatedUrl,
          id: cacheId,
          mode: linkMode,
          expires: expiresIn,
          expires_human: formatDuration(expiresIn),
          created: Date.now(),
          passwordProtected: !!password,
          maxClicks: linkData.maxClicks,
          notes,
          linkLength
        },
        metadata: {
          encoding:
            linkMode === 'long'
              ? {
                  layers: encodingMetadata.layers?.length,
                  complexity: encodingMetadata.complexity,
                  iterations: encodingMetadata.metadata?.iterations,
                  encodingTime: linkMetadata.encodingTime
                }
              : null
        },
        meta: {
          apiVersion: 'v2',
          requestId: req.id,
          timestamp: new Date().toISOString()
        }
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * Bulk create links
   */
  v2Router.post('/bulk', async (req, res, next) => {
    try {
      const validated = validator.validate('bulkLinks', req.body);
      const MAX_BATCH = 100;

      if (validated.links.length > MAX_BATCH) {
        throw new ValidationError(
          `Maximum ${MAX_BATCH} links per request`
        );
      }

      const results = await Promise.allSettled(
        validated.links.map(async (link, index) => {
          try {
            const target = link.url;
            if (!validateUrl(target)) {
              throw new ValidationError('Invalid URL at index ' + index);
            }

            const password = link.password;
            const maxClicks = link.maxClicks;
            const expiresIn = link.expiresIn ? parseTTL(link.expiresIn) : LINK_TTL_SEC;
            const notes = link.notes || '';
            const linkMode = link.linkMode || CONFIG.LINK_LENGTH_MODE;

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

            const passwordHash = password
              ? await bcrypt.hash(password, CONFIG.BCRYPT_ROUNDS)
              : null;

            const linkData = {
              target,
              created: Date.now(),
              expiresAt: Date.now() + expiresIn * 1000,
              passwordHash,
              maxClicks: maxClicks ? Math.min(parseInt(maxClicks, 10), 10000) : null,
              currentClicks: 0,
              notes,
              linkMode,
              linkMetadata,
              encodingMetadata
            };

            cacheSet(linkCache, 'link', cacheId, linkData, expiresIn);

            if (getDbPool()) {
              try {
                await queryWithTimeout(
                  `INSERT INTO links (id, target_url, created_at, expires_at, creator_ip, password_hash, max_clicks, current_clicks, link_mode, link_metadata, encoding_metadata, api_version)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'v2')`,
                  [
                    cacheId,
                    target,
                    new Date(),
                    new Date(Date.now() + expiresIn * 1000),
                    req.ip,
                    passwordHash,
                    linkData.maxClicks,
                    0,
                    linkMode,
                    JSON.stringify(linkMetadata),
                    JSON.stringify(encodingMetadata)
                  ]
                );
              } catch (dbErr) {
                logger.warn('Failed to store bulk link:', sanitizeLogEntry(dbErr.message));
              }
            }

            stats.generatedLinks++;
            linkGenerations.inc({ mode: linkMode, version: 'v2' });

            return {
              index,
              success: true,
              url: generatedUrl,
              id: cacheId,
              mode: linkMode
            };
          } catch (err) {
            return {
              index,
              success: false,
              error: err.message
            };
          }
        })
      );

      const successful = results.filter(
        (r) => r.status === 'fulfilled' && r.value.success
      ).length;
      const failed = validated.links.length - successful;

      res.json({
        success: true,
        data: {
          results: results.map((r) =>
            r.status === 'fulfilled'
              ? r.value
              : { success: false, error: r.reason?.message }
          ),
          summary: {
            total: validated.links.length,
            successful,
            failed
          }
        },
        meta: {
          apiVersion: 'v2',
          requestId: req.id,
          timestamp: new Date().toISOString()
        }
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * Get detailed statistics for a link (v2)
   */
  v2Router.get('/stats/:id', async (req, res, next) => {
    try {
      const linkId = req.params.id;
      if (!linkId.match(/^[a-f0-9]{32}$/i)) {
        throw new ValidationError('Invalid link ID format');
      }

      const linkData = cacheGet(linkCache, 'link', linkId);
      let statsRes = {
        exists: !!linkData,
        created: linkData?.created,
        expiresAt: linkData?.expiresAt,
        target_url: linkData?.target,
        clicks: linkData?.currentClicks || 0,
        maxClicks: linkData?.maxClicks,
        passwordProtected: !!linkData?.passwordHash,
        notes: linkData?.notes || '',
        linkMode: linkData?.linkMode,
        linkLength: linkData?.linkMetadata?.length || 0,
        encodingLayers: linkData?.encodingMetadata?.layers?.length || 0,
        encodingComplexity: linkData?.encodingMetadata?.complexity || 0
      };

      let clickStats = {
        uniqueVisitors: 0,
        countries: {},
        devices: {},
        hourly: [],
        daily: [],
        recentClicks: []
      };

      if (getDbPool() && linkData) {
        try {
          const result = await queryWithTimeout(
            `SELECT COUNT(*) as total_clicks, COUNT(DISTINCT ip) as unique_visitors, AVG(decoding_time_ms) as avg_decoding_time 
             FROM clicks WHERE link_id = $1`,
            [linkId]
          );

          const countryResult = await queryWithTimeout(
            `SELECT country, COUNT(*) as count FROM clicks WHERE link_id=$1 AND country IS NOT NULL GROUP BY country LIMIT 50`,
            [linkId]
          );

          const deviceResult = await queryWithTimeout(
            `SELECT device_type, COUNT(*) as count FROM clicks WHERE link_id=$1 AND device_type IS NOT NULL GROUP BY device_type`,
            [linkId]
          );

          const dailyResult = await queryWithTimeout(
            `SELECT DATE(created_at) as date, COUNT(*) as count FROM clicks WHERE link_id=$1 AND created_at > NOW() - INTERVAL '30 days' GROUP BY DATE(created_at) LIMIT 100`,
            [linkId]
          );

          const recentResult = await queryWithTimeout(
            `SELECT ip, country, device_type, decoding_time_ms, created_at FROM clicks WHERE link_id=$1 ORDER BY created_at DESC LIMIT 20`,
            [linkId]
          );

          if (result.rows[0]) {
            statsRes = { ...statsRes, ...result.rows[0] };
          }

          if (countryResult.rows.length) {
            clickStats.countries = Object.fromEntries(
              countryResult.rows.map((r) => [r.country, parseInt(r.count, 10)])
            );
          }

          if (deviceResult.rows.length) {
            clickStats.devices = Object.fromEntries(
              deviceResult.rows.map((r) => [r.device_type, parseInt(r.count, 10)])
            );
          }

          clickStats.daily = dailyResult.rows.map((r) => ({
            date: r.date,
            count: parseInt(r.count, 10)
          }));

          clickStats.recentClicks = recentResult.rows;
        } catch (dbErr) {
          logger.warn('Failed to fetch click stats:', sanitizeLogEntry(dbErr.message));
        }
      }

      res.json({
        success: true,
        data: {
          link: statsRes,
          clicks: clickStats
        },
        meta: {
          apiVersion: 'v2',
          requestId: req.id,
          timestamp: new Date().toISOString()
        }
      });
    } catch (err) {
      next(err);
    }
  });

  // Register API versions
  apiVersionManager.registerVersion('v1', v1Router, {
    deprecated: false,
    description: 'Original API version'
  });

  apiVersionManager.registerVersion('v2', v2Router, {
    deprecated: false,
    description: 'Enhanced API with bulk operations, request signing, and encryption'
  });

  apiVersionManager.registerMiddleware('v2', (req, res, next) => {
    res.setHeader('X-API-Enhanced', 'true');
    next();
  });

  app.use('/api', apiVersionManager.versionMiddleware({ strict: CONFIG.API_VERSION_STRICT }));
  app.use('/api/v1', v1Router);
  app.use('/api/v2', v2Router);

  app.get('/api/versions', (req, res) => {
    res.json({
      current: req.apiVersion || apiVersionManager.getLatestVersion(),
      versions: apiVersionManager.generateVersionDocs(),
      default: apiVersionManager.defaultVersion,
      supported: CONFIG.SUPPORTED_API_VERSIONS
    });
  });

  // ----- Public redirect endpoints -----

  /**
   * Short link redirect with bot detection and challenge
   */
  app.get('/v/:id', strictLimiter, async (req, res, next) => {
    try {
      const linkId = req.params.id;
      if (!linkId.match(/^[a-f0-9]{32}$/i)) {
        return res.redirect(CONFIG.BOT_URLS[crypto.randomInt(0, CONFIG.BOT_URLS.length)]);
      }

      const deviceInfo = req.deviceInfo;
      const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '0.0.0.0';
      const showQr = req.query.qr === 'true';
      const embed = req.query.embed === 'true';

      // Rate limit per IP/link combo
      const linkKey = `${linkId}:${ip}`;
      const requestCount = cacheGet(linkRequestCache, 'linkReq', linkKey) || 0;
      if (requestCount >= MAX_IP_REQUESTS) {
        if (botBlocks && typeof botBlocks.inc === 'function') {
          botBlocks.inc({ reason: 'rate_limit' });
        } else {
          stats.botBlocks++;
        }
        return res.redirect(CONFIG.BOT_URLS[crypto.randomInt(0, CONFIG.BOT_URLS.length)]);
      }
      cacheSet(linkRequestCache, 'linkReq', linkKey, requestCount + 1);

      const country = await getCountryCode(req);
      if (isLikelyBot(req)) {
        return res.redirect(
          CONFIG.BOT_URLS[crypto.randomInt(0, CONFIG.BOT_URLS.length)]
        );
      }

      let data = cacheGet(linkCache, 'link', linkId);

      // Check database if not in cache
      if (!data && getDbPool()) {
        try {
          const result = await queryWithTimeout(
            'SELECT * FROM links WHERE id = $1 AND expires_at > NOW()',
            [linkId]
          );
          if (result.rows.length) {
            const row = result.rows[0];
            data = {
              target: row.target_url,
              passwordHash: row.password_hash,
              maxClicks: row.max_clicks,
              currentClicks: row.current_clicks,
              expiresAt: new Date(row.expires_at).getTime(),
              created: new Date(row.created_at).getTime(),
              notes: row.notes,
              linkMode: row.link_mode,
              linkMetadata: row.link_metadata,
              encodingMetadata: row.encoding_metadata
            };

            const ttl = Math.max(60, Math.floor((data.expiresAt - Date.now()) / 1000));
            cacheSet(linkCache, 'link', linkId, data, ttl);
          }
        } catch (dbErr) {
          logger.warn('Failed to fetch link from DB:', sanitizeLogEntry(dbErr.message));
        }
      }

      // Check if link exists and is valid
      if (!data || data.expiresAt < Date.now() || (data.maxClicks && data.currentClicks >= data.maxClicks)) {
        stats.expiredLinks++;
        return res.redirect(`/expired?target=${encodeURIComponent(CONFIG.BOT_URLS[0])}`);
      }

      data.currentClicks = (data.currentClicks || 0) + 1;
      data.lastAccessed = Date.now();
      cacheSet(linkCache, 'link', linkId, data);

      // Embed mode
      if (embed) {
        return res.send(
          `<!DOCTYPE html><html><head><title>Embedded</title><style>body{margin:0;overflow:hidden}</style></head><body><iframe src="${data.target}" sandbox="allow-scripts allow-same-origin allow-forms allow-popups" style="width:100vw;height:100vh;border:none"></iframe></body></html>`
        );
      }

      // Password protected
      if (data.passwordHash) {
        const nonce = res.locals.nonce;
        return res.send(
          passwordProtectedPage(linkId, req.query.error === 'true' ? 'Invalid password' : '', nonce)
        );
      }

      // QR code
      if (showQr) {
        const qrData = await QRCode.toDataURL(data.target);
        return res.send(qrCodePage(data.target, qrData, res.locals.nonce));
      }

      // Mobile or no challenge
      if (deviceInfo.isMobile || CONFIG.DISABLE_DESKTOP_CHALLENGE) {
        stats.successfulRedirects++;
        return res.send(
          `<meta http-equiv="refresh" content="0;url=${data.target}">`
        );
      }

      // Desktop browser challenge
      const hpSuffix = crypto.randomBytes(2).toString('hex');
      const nonce = res.locals.nonce;
      const challenge = createBrowserChallenge(data.target, hpSuffix);
      const obfuscated = JavaScriptObfuscator.obfuscate(challenge, {
        compact: true,
        controlFlowFlattening: true,
        stringArray: true,
        disableConsoleOutput: true
      }).getObfuscatedCode();

      res.send(
        createChallengeHtml(
          obfuscated,
          hpSuffix,
          nonce,
          CONFIG.BOT_URLS[0],
          PASSWORD_PROTECTED_TIMEOUT
        )
      );
    } catch (err) {
      next(err);
    }
  });

  /**
   * Long link redirect with encoded URL decoding
   */
  app.get('/r/*', strictLimiter, async (req, res, next) => {
    try {
      const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '0.0.0.0';
      const ipKey = `r:${ip}`;
      const requestCount = cacheGet(linkRequestCache, 'linkReq', ipKey) || 0;

      if (requestCount >= MAX_LONG_LINK_REQUESTS) {
        if (botBlocks && typeof botBlocks.inc === 'function') {
          botBlocks.inc({ reason: 'rate_limit' });
        } else {
          stats.botBlocks++;
        }
        return res.redirect(
          CONFIG.BOT_URLS[crypto.randomInt(0, CONFIG.BOT_URLS.length)]
        );
      }
      cacheSet(linkRequestCache, 'linkReq', ipKey, requestCount + 1);

      const country = await getCountryCode(req);
      if (isLikelyBot(req)) {
        return res.redirect(
          CONFIG.BOT_URLS[crypto.randomInt(0, CONFIG.BOT_URLS.length)]
        );
      }

      const decodeResult = await decodeLongLink(req);
      const redirectTarget = decodeResult.success ? decodeResult.target : CONFIG.TARGET_URL;

      stats.successfulRedirects++;

      if (req.deviceInfo.isMobile || CONFIG.DISABLE_DESKTOP_CHALLENGE) {
        return res.send(
          `<meta http-equiv="refresh" content="0;url=${redirectTarget}">`
        );
      }

      const hpSuffix = crypto.randomBytes(2).toString('hex');
      const nonce = res.locals.nonce;
      const challenge = createBrowserChallenge(redirectTarget, hpSuffix);
      const obfuscated = JavaScriptObfuscator.obfuscate(challenge, {
        compact: true,
        controlFlowFlattening: true,
        stringArray: true,
        disableConsoleOutput: true
      }).getObfuscatedCode();

      res.send(
        createChallengeHtml(
          obfuscated,
          hpSuffix,
          nonce,
          CONFIG.BOT_URLS[0],
          PASSWORD_PROTECTED_TIMEOUT
        )
      );
    } catch (err) {
      next(err);
    }
  });

  /**
   * Password verification endpoint
   */
  app.post('/v/:id/verify', express.json({ limit: '1kb' }), async (req, res, next) => {
    try {
      const linkId = req.params.id;
      if (!linkId.match(/^[a-f0-9]{32}$/i)) {
        throw new ValidationError('Invalid link ID');
      }

      const { password } = req.body;
      if (!password || typeof password !== 'string') {
        throw new ValidationError('Password required');
      }

      let linkData = cacheGet(linkCache, 'link', linkId);

      if (!linkData && getDbPool()) {
        try {
          const result = await queryWithTimeout(
            'SELECT * FROM links WHERE id = $1 AND expires_at > NOW()',
            [linkId]
          );

          if (result.rows.length) {
            const row = result.rows[0];
            linkData = {
              target: row.target_url,
              passwordHash: row.password_hash,
              maxClicks: row.max_clicks,
              currentClicks: row.current_clicks,
              expiresAt: new Date(row.expires_at).getTime(),
              created: new Date(row.created_at).getTime()
            };

            const ttl = Math.max(60, Math.floor((linkData.expiresAt - Date.now()) / 1000));
            cacheSet(linkCache, 'link', linkId, linkData, ttl);
          }
        } catch (dbErr) {
          logger.warn('Password verify DB error:', sanitizeLogEntry(dbErr.message));
        }
      }

      if (!linkData || linkData.expiresAt < Date.now()) {
        throw new AppError('Link not found or expired', 404, 'LINK_NOT_FOUND');
      }

      if (!linkData.passwordHash) {
        return res.json({ success: true, target: linkData.target, redirect: true });
      }

      const valid = await bcrypt.compare(password, linkData.passwordHash);
      if (!valid) {
        throw new AppError('Invalid password', 401, 'INVALID_PASSWORD');
      }

      linkData.lastAccessed = Date.now();
      cacheSet(linkCache, 'link', linkId, linkData);

      if (getDbPool()) {
        try {
          await queryWithTimeout('UPDATE links SET last_accessed = CURRENT_TIMESTAMP WHERE id = $1', [
            linkId
          ]);
        } catch (dbErr) {
          logger.warn('Failed to update link:', sanitizeLogEntry(dbErr.message));
        }
      }

      res.json({ success: true, target: linkData.target });
    } catch (err) {
      next(err);
    }
  });

  // ----- Admin routes -----

  app.get('/admin/login', (req, res) => {
    if (req.session?.authenticated) {
      return res.redirect('/admin');
    }

    req.session.regenerate(async (err) => {
      if (err) {
        logger.error('Session regeneration error:', sanitizeLogEntry(err.message));
      }

      const csrfToken = crypto.randomBytes(32).toString('hex');
      req.session.csrfToken = csrfToken;
      const nonce = crypto.randomBytes(16).toString('hex');

      try {
        const loginPath = path.join(__dirname, 'public', 'login.html');
        let loginHtml = await fs.readFile(loginPath, 'utf8');

        // Prepare all template variables
        const templateVars = {
          csrfToken: JSON.stringify(csrfToken),
          ADMIN_USERNAME: JSON.stringify(CONFIG.ADMIN_USERNAME),
          LOGIN_ATTEMPTS_MAX: CONFIG.LOGIN_ATTEMPTS_MAX || 10,
          LOGIN_BLOCK_DURATION: CONFIG.LOGIN_BLOCK_DURATION || 3600000,
          version: JSON.stringify('4.3.0'),
          MFA_ENABLED: CONFIG.MFA_ENABLED === true ? 'true' : 'false',
          WEBAUTHN_ENABLED: CONFIG.WEBAUTHN_ENABLED === true ? 'true' : 'false',
          DEBUG: CONFIG.DEBUG === true ? 'true' : 'false',
          SESSION_TTL: CONFIG.SESSION_TTL || 86400,
          NONCE: JSON.stringify(nonce)
        };

        // Replace all template variables
        // Handle both {{key|json}} for JSON contexts and {{key}} for attribute contexts
        for (const [key, value] of Object.entries(templateVars)) {
          // Replace {{key|json}} with value as-is (for JSON.parse in scripts)
          const jsonPattern = new RegExp(`{{${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\|json}}`, 'g');
          loginHtml = loginHtml.replace(jsonPattern, value);
          
          // Replace {{key}} with unquoted value if it's JSON-stringified (for HTML attributes)
          let plainValue = value;
          if (typeof value === 'string' && value.startsWith('"') && value.endsWith('"')) {
            plainValue = value.slice(1, -1);  // Remove JSON quotes
          }
          const plainPattern = new RegExp(`{{${key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}}}`, 'g');
          loginHtml = loginHtml.replace(plainPattern, plainValue);
        }

        // Set CSP header
        res.setHeader(
          'Content-Security-Policy',
          `default-src 'self'; script-src 'self' 'nonce-${nonce}' https://cdnjs.cloudflare.com https://cdn.socket.io https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data: https:; font-src 'self' https://cdnjs.cloudflare.com data:;`
        );

        res.send(loginHtml);
      } catch (err) {
        logger.error('Failed to read login page:', sanitizeLogEntry(err.message));
        res.status(500).send('Login page not found');
      }
    });
  });

  app.post('/admin/login', loginLimiter, csrfProtection, express.json(), async (req, res, next) => {
    try {
      const { username, password, remember } = req.body;
      const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';

      if (typeof username !== 'string' || typeof password !== 'string') {
        throw new ValidationError('Invalid credentials format');
      }

      const validUsername = username === CONFIG.ADMIN_USERNAME;
      const validPassword = await bcrypt.compare(password, CONFIG.ADMIN_PASSWORD_HASH);

      if (validUsername && validPassword) {
        req.session.regenerate((err) => {
          if (err) return next(err);

          req.session.authenticated = true;
          req.session.user = username;
          req.session.loginTime = Date.now();
          req.session.createdAt = Date.now();
          req.session.csrfToken = crypto.randomBytes(32).toString('hex');

          if (remember) {
            req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
          } else {
            req.session.cookie.maxAge = 24 * 60 * 60 * 1000; // 1 day
          }

          if (getDbPool()) {
            queryWithTimeout(
              'INSERT INTO user_sessions (session_id, user_id, ip, user_agent) VALUES ($1,$2,$3,$4)',
              [req.session.id, username, ip, req.headers['user-agent']?.substring(0, 200)]
            ).catch((err) => {
              logger.warn('Failed to log session:', sanitizeLogEntry(err.message));
            });
          }

          logger.info('Successful admin login', { ip, username });
          res.json({ success: true });
        });
      } else {
        logger.warn('Failed admin login attempt', { ip, username });
        throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
      }
    } catch (err) {
      next(err);
    }
  });

  app.get('/admin', ensureAuthenticated, async (req, res) => {
    try {
      const indexPath = path.join(__dirname, 'public', 'index.html');
      let html = await fs.readFile(indexPath, 'utf8');

      const dbPool = getDbPool();
      const redisClient = getRedis();
      const queues = getQueues();

      const replacements = {
        '{{METRICS_API_KEY}}': CONFIG.METRICS_API_KEY,
        '{{TARGET_URL}}': CONFIG.TARGET_URL,
        '{{csrfToken}}': req.session.csrfToken,
        '{{dbPoolStatus}}': dbPool ? 'connected' : 'disconnected',
        '{{redisStatus}}': redisClient?.status === 'ready' ? 'connected' : 'disconnected',
        '{{redirectQueueStatus}}': queues.redirectQueue ? 'enabled' : 'disabled',
        '{{encodingQueueStatus}}': queues.encodingQueue ? 'enabled' : 'disabled',
        '{{bullBoardPath}}': CONFIG.BULL_BOARD_PATH,
        '{{version}}': '4.3.0',
        '{{nodeEnv}}': CONFIG.NODE_ENV,
        '{{enableEncryption}}': CONFIG.ENABLE_ENCRYPTION,
        '{{encryptionEnabled}}': CONFIG.ENABLE_ENCRYPTION,
        '{{keyRotationDays}}': CONFIG.ENCRYPTION_KEY_ROTATION_DAYS
      };

      for (const [key, val] of Object.entries(replacements)) {
        const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        html = html.replace(new RegExp(escapedKey, 'g'), String(val));
      }

      const nonce = crypto.randomBytes(16).toString('hex');
      res.locals.nonce = nonce;

      res.setHeader(
        'Content-Security-Policy',
        `default-src 'self'; script-src 'self' 'nonce-${nonce}' https://cdn.socket.io https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;`
      );

      html = html.replace(/<script nonce="{{NONCE}}">/g, `<script nonce="${nonce}">`);
      res.send(html);
    } catch (err) {
      logger.error('Failed to serve dashboard:', sanitizeLogEntry(err.message));
      res.status(500).send('Dashboard not found');
    }
  });

  app.post('/admin/logout', (req, res) => {
    if (getDbPool() && req.session?.id) {
      queryWithTimeout(
        'UPDATE user_sessions SET revoked_at = NOW() WHERE session_id = $1',
        [req.session.id]
      ).catch((err) => {
        logger.warn('Failed to revoke session:', sanitizeLogEntry(err.message));
      });
    }

    req.session.destroy((err) => {
      if (err) logger.error('Logout error:', sanitizeLogEntry(err.message));
      res.clearCookie('redirector.sid');
      res.json({ success: true });
    });
  });

  app.post('/admin/clear-cache', csrfProtection, ensureAuthenticated, (req, res) => {
    try {
      const caches = getCaches();
      for (const cache of Object.values(caches)) {
        if (cache.clear) cache.clear();
      }

      for (const key in cacheStats) {
        cacheStats[key].hits = 0;
        cacheStats[key].misses = 0;
      }

      logger.info('Cache cleared by admin', { user: req.session.user });
      res.json({ success: true, message: 'Cache cleared' });
    } catch (err) {
      res.status(500).json({ error: 'Failed to clear cache' });
    }
  });

  app.get('/admin/export-logs', ensureAuthenticated, async (req, res, next) => {
    try {
      const logsPath = path.join(__dirname, 'logs', 'combined-' + new Date().toISOString().split('T')[0] + '.log');
      const logs = await fs.readFile(logsPath, 'utf8');

      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Content-Disposition', `attachment; filename="logs-${Date.now()}.txt"`);
      res.send(logs);
    } catch (err) {
      logger.error('Failed to export logs:', sanitizeLogEntry(err.message));
      res.status(404).json({ error: 'Logs not found' });
    }
  });

  app.get('/api/export/:id', ensureAuthenticated, async (req, res, next) => {
    try {
      const linkId = req.params.id;
      if (!linkId.match(/^[a-f0-9]{32}$/i)) {
        throw new ValidationError('Invalid link ID');
      }

      const format = req.query.format || 'json';

      if (!getDbPool()) {
        throw new AppError('Database not available', 503, 'DATABASE_UNAVAILABLE');
      }

      const result = await queryWithTimeout(
        `SELECT id, link_id, ip, country, device_type, decoding_time_ms, created_at 
         FROM clicks WHERE link_id = $1 ORDER BY created_at DESC LIMIT 10000`,
        [linkId]
      );

      if (format === 'csv') {
        const headers = ['id', 'link_id', 'ip', 'country', 'device_type', 'decoding_time_ms', 'created_at'];
        const csv = [
          headers.join(','),
          ...result.rows.map((row) =>
            headers.map((h) => {
              const val = row[h] || '';
              return typeof val === 'string' ? `"${val.replace(/"/g, '""')}"` : val;
            }).join(',')
          )
        ].join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="clicks-${linkId}.csv"`);
        res.send(csv);
      } else {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="clicks-${linkId}.json"`);
        res.json(result.rows);
      }
    } catch (err) {
      next(err);
    }
  });

  app.get('/admin/security/monitor', ensureAuthenticated, (req, res) => {
    res.json({
      blockedIPs: [],
      activeAttacks: [],
      totalAttempts: 0,
      activeSessions: [],
      rateLimitStats: {},
      signatureStats: stats.signatures,
      memoryLeak: stats.memoryLeak,
      circuitBreakers: getBreakerMonitor()?.getStatus() || {}
    });
  });

  app.post('/admin/force-gc', csrfProtection, ensureAuthenticated, (req, res) => {
    if (global.gc) {
      global.gc();
      logger.info('Garbage collection triggered by admin');
      res.json({ success: true, message: 'Garbage collection forced' });
    } else {
      res.status(400).json({ success: false, message: 'GC not available (run with --expose-gc)' });
    }
  });

  app.get('/admin/circuit-breakers', ensureAuthenticated, (req, res) => {
    res.json({
      status: getBreakerMonitor()?.getStatus() || {},
      metrics: getBreakerMonitor()?.getMetrics() || {}
    });
  });

  // ----- QR code endpoints -----

  app.get('/qr', async (req, res, next) => {
    try {
      const url = req.query.url || CONFIG.TARGET_URL;
      const size = Math.min(parseInt(req.query.size, 10) || 300, 1000);
      const format = req.query.format || 'json';

      if (!validateUrl(url)) {
        throw new ValidationError('Invalid URL');
      }

      const cacheKey = crypto
        .createHash('md5')
        .update(`${url}:${size}:${format}`)
        .digest('hex');

      let qrData = cacheGet(qrCache, 'qr', cacheKey);

      if (!qrData) {
        if (format === 'png') {
          qrData = await QRCode.toBuffer(url, { width: size, margin: 2, type: 'image/png' });
        } else {
          qrData = await QRCode.toDataURL(url, { width: size, margin: 2 });
        }
        cacheSet(qrCache, 'qr', cacheKey, qrData, 3600);
      }

      if (format === 'png') {
        res.setHeader('Content-Type', 'image/png');
        res.send(qrData);
      } else {
        res.json({ qr: qrData, url, size });
      }
    } catch (err) {
      next(err);
    }
  });

  app.get('/qr/download', async (req, res, next) => {
    try {
      const url = req.query.url || CONFIG.TARGET_URL;
      const size = Math.min(parseInt(req.query.size, 10) || 300, 1000);

      if (!validateUrl(url)) {
        throw new ValidationError('Invalid URL');
      }

      const qrBuffer = await QRCode.toBuffer(url, { width: size, margin: 2, type: 'image/png' });

      res.setHeader('Content-Type', 'image/png');
      res.setHeader('Content-Disposition', `attachment; filename="qrcode-${Date.now()}.png"`);
      res.send(qrBuffer);
    } catch (err) {
      next(err);
    }
  });

  app.get('/expired', (req, res) => {
    const originalTarget = req.query.target || CONFIG.BOT_URLS[0];
    const nonce = res.locals.nonce;

    res.send(createExpiredPage(originalTarget, nonce));
  });

  // ----- 404 fallback -----
  app.use((req, res) => {
    res.status(404).redirect(
      CONFIG.BOT_URLS[crypto.randomInt(0, CONFIG.BOT_URLS.length)]
    );
  });

  // ----- Global error handler -----
  app.use((err, req, res, next) => {
    const errorId = uuidv4();
    const statusCode = err.statusCode || 500;
    const errorCode = err.code || 'INTERNAL_ERROR';

    logger.error('Request error', {
      errorId,
      code: errorCode,
      message: sanitizeLogEntry(err.message),
      stack: err.stack?.substring(0, 500),
      id: req.id,
      path: req.path,
      method: req.method,
      ip: req.ip,
      url: req.originalUrl
    });

    totalRequests.inc({
      method: req.method,
      path: req.path,
      status: statusCode,
      version: req.apiVersion || 'unknown'
    });

    // Operational errors
    if (err instanceof AppError) {
      const response = {
        error: err.message,
        code: err.code,
        id: req.id,
        errorId,
        timestamp: new Date().toISOString()
      };

      if (err instanceof ValidationError && err.details) {
        response.errors = err.details;
      }

      return res.status(statusCode).json(response);
    }

    // Unknown errors
    if (!res.headersSent) {
      if (req.accepts('html')) {
        res.redirect(CONFIG.BOT_URLS[crypto.randomInt(0, CONFIG.BOT_URLS.length)]);
      } else {
        res.status(500).json({
          error: 'Internal server error',
          code: 'INTERNAL_ERROR',
          id: req.id,
          errorId
        });
      }
    }
  });

  return { app, io };
}

// ==================== UTILITY FUNCTIONS ====================

function getConfigForClient() {
  const dbPool = getDbPool();
  const redisClient = getRedis();
  const queues = getQueues();
  const keyManager = getKeyManager();

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
    uptime: process.uptime(),
    version: '4.3.0',
    nodeEnv: CONFIG.NODE_ENV,
    databaseEnabled: !!dbPool,
    redisEnabled: !!redisClient,
    queuesEnabled: !!queues.redirectQueue,
    encryptionEnabled: keyManager?.initialized || false,
    apiVersions: CONFIG.SUPPORTED_API_VERSIONS,
    requestSigning: true,
    memoryLeakDetection: stats.memoryLeak.detected,
    circuitBreakers: Object.keys(getBreakerMonitor()?.getStatus() || {})
  };
}

async function handleAdminCommand(cmd, socket) {
  switch (cmd.action) {
    case 'clearCache': {
      const caches = getCaches();
      for (const cache of Object.values(caches)) {
        if (cache.clear) cache.clear();
      }
      socket.emit('notification', { type: 'success', message: 'Cache cleared' });
      break;
    }

    case 'getStats':
      socket.emit('stats', getStats());
      break;

    case 'getConfig':
      socket.emit('config', getConfigForClient());
      break;

    case 'getLinks':
      try {
        const links = await getAllLinks();
        socket.emit('links', links);
      } catch (err) {
        socket.emit('notification', { type: 'error', message: 'Failed to fetch links' });
      }
      break;

    case 'getCacheStats':
      socket.emit('cacheStats', cacheStats);
      break;

    case 'getSystemMetrics':
      socket.emit('systemMetrics', {
        memory: process.memoryUsage(),
        uptime: process.uptime(),
        memoryLeak: stats.memoryLeak
      });
      break;

    case 'rotateKeys': {
      const keyManager = getKeyManager();
      if (keyManager?.initialized) {
        try {
          await keyManager.generateNewKey();
          socket.emit('notification', { type: 'success', message: 'New encryption key generated' });
        } catch (err) {
          socket.emit('notification', { type: 'error', message: 'Key rotation failed' });
        }
      } else {
        socket.emit('notification', { type: 'error', message: 'Encryption not enabled' });
      }
      break;
    }

    case 'listKeys': {
      const keyManager = getKeyManager();
      if (keyManager?.initialized) {
        try {
          const keys = await keyManager.listKeys();
          socket.emit('keys', keys);
        } catch (err) {
          socket.emit('notification', { type: 'error', message: 'Failed to list keys' });
        }
      }
      break;
    }

    case 'forceGC':
      if (global.gc) {
        global.gc();
        socket.emit('notification', { type: 'success', message: 'Garbage collection forced' });
      } else {
        socket.emit('notification', {
          type: 'error',
          message: 'GC not available (run with --expose-gc)'
        });
      }
      break;

    case 'getCircuitBreakers':
      socket.emit('circuitBreakers', {
        status: getBreakerMonitor()?.getStatus(),
        metrics: getBreakerMonitor()?.getMetrics()
      });
      break;

    default:
      socket.emit('notification', { type: 'error', message: 'Unknown command' });
  }
}

function createBrowserChallenge(target, hpSuffix) {
  return `(function(){const T='${target.replace(/'/g, "\\'")}';let m=0,e=0,lx=0,ly=0,lt=Date.now();document.addEventListener('mousemove',function(ev){if(lx&&ly){const dt=(Date.now()-lt)/1000||1;const distance=Math.hypot(ev.clientX-lx,ev.clientY-ly);const speed=distance/dt;e=Math.log2(1+speed);m++;}lx=ev.clientX;ly=ev.clientY;lt=Date.now();},{passive:true});setTimeout(function(){const sus=e<2.5||m<2||document.getElementById('hp_${hpSuffix}')?.value;location.href=sus?'about:blank':T;},1200);})();`;
}

function createChallengeHtml(obfuscated, hpSuffix, nonce, botUrl, timeout) {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="${Math.ceil(timeout / 1000)};url=${botUrl}"><style nonce="${nonce}">*{margin:0;padding:0}body{background:#0a0a0a;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}.spinner{width:40px;height:40px;border:3px solid #2a2a2a;border-top-color:#8a8a8a;border-radius:50%;margin:20px auto;animation:spin 1s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}.hidden{position:absolute;width:1px;height:1px;overflow:hidden}.message{text-align:center}.message p{margin-top:10px;color:#666}</style></head><body><div class="message"><div class="spinner"></div><p>Verifying browser...</p><div class="hidden"><input id="hp_${hpSuffix}"></div></div><script nonce="${nonce}">${obfuscated}</script></body></html>`;
}

function passwordProtectedPage(linkId, error, nonce) {
  return `<!DOCTYPE html><html><head><title>Password Protected</title><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css"><style nonce="${nonce}">*{margin:0;padding:0;box-sizing:border-box}body{min-height:100vh;background:#000;color:#ddd;display:flex;align-items:center;justify-content:center;padding:20px}.login-wrapper{max-width:1000px;background:#0a0a0a;border-radius:28px;display:flex}.form-side{flex:1;padding:3rem;background:linear-gradient(135deg,#0f0f0f,#080808)}h1{font-size:2.5rem;margin-bottom:0.5rem}p{color:#888;margin-bottom:2rem}.alert{background:rgba(239,68,68,0.1);border-left:4px solid #ef4444;color:#fecaca;padding:1rem;border-radius:12px;margin-bottom:1.5rem;display:${error ? 'flex' : 'none'}}.input-wrapper{position:relative;margin-bottom:1.5rem}input{width:100%;padding:1rem;background:rgba(20,20,20,0.7);border:1px solid #222;border-radius:12px;color:#eee}button{width:100%;padding:1rem;background:#5a5a5a;border:none;border-radius:14px;color:white;cursor:pointer}</style></head><body><div class="login-wrapper"><div class="form-side"><h1>Protected Link</h1><p>This link requires a password</p><div class="alert" id="errorAlert"><span id="errorMessage">${error}</span></div><form id="passwordForm"><div class="input-wrapper"><input type="password" id="password" placeholder="Enter password" autofocus required></div><button type="submit">Access Link</button></form></div></div><script nonce="${nonce}">document.getElementById('passwordForm').addEventListener('submit',async e=>{e.preventDefault();const password=document.getElementById('password').value;try{const response=await fetch('/v/${linkId}/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});const data=await response.json();if(response.ok&&data.success){window.location.href=data.target;}else{document.getElementById('errorMessage').textContent=data.error||'Invalid password';document.getElementById('errorAlert').style.display='flex';}}catch(err){document.getElementById('errorMessage').textContent='Connection error';document.getElementById('errorAlert').style.display='flex';}});</script></body></html>`;
}

function qrCodePage(target, qrData, nonce) {
  return `<!DOCTYPE html><html><head><title>QR Code</title><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="5;url=${target}"><style nonce="${nonce}">body{min-height:100vh;background:#000;color:#ddd;display:flex;align-items:center;justify-content:center;margin:0;padding:20px}.card{background:#0a0a0a;padding:2rem;border-radius:24px;text-align:center;max-width:400px;border:1px solid #1a1a1a}h2{font-size:1.5rem;margin-bottom:1rem}img{max-width:100%;border-radius:16px;margin:1rem 0}.countdown{color:#4ade80;margin-top:1rem}</style></head><body><div class="card"><h2>📱 Scan QR Code</h2><img src="${qrData}" alt="QR Code"><p>Or continue to website...</p><div class="countdown">Redirecting in <span id="countdown">5</span> seconds</div></div><script nonce="${nonce}">let time=5;const interval=setInterval(()=>{time--;document.getElementById('countdown').textContent=time;if(time<=0){clearInterval(interval);window.location.href='${target}';}},1000);</script></body></html>`;
}

function createExpiredPage(originalTarget, nonce) {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Link Expired</title><style nonce="${nonce}">body{background:#000;color:#ddd;padding:10px;display:flex;align-items:center;justify-content:center;min-height:100vh}.card{background:#0a0a0a;padding:2rem;border-radius:24px;text-align:center;max-width:480px;border:1px solid #1a1a1a}h1{font-size:2rem;margin:0.5rem 0}p{color:#888;margin:1rem 0}a{display:inline-block;margin-top:1rem;padding:0.75rem 1.5rem;background:#5a5a5a;color:white;text-decoration:none;border-radius:8px;transition:background 0.3s}a:hover{background:#7a7a7a}</style></head><body><div class="card"><span style="font-size:3rem">⌛</span><h1>Link Expired</h1><p>This link has expired and is no longer available.</p><a href="${originalTarget}">Continue to Website</a></div></body></html>`;
}

module.exports = { createServer };
