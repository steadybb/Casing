// core.js – All shared classes, configuration, caches, utilities, encoding, and initialization
require('dotenv').config();
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const Joi = require('joi');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const Redis = require('ioredis');
const { Queue } = require('bull');
const NodeCache = require('node-cache');
const Keyv = require('keyv');
const KeyvFile = require('keyv-file').KeyvFile;
const { v4: uuidv4 } = require('uuid');
const sanitizeHtml = require('sanitize-html');
const ipaddr = require('ipaddr.js');
const { RateLimiterMemory, RateLimiterRedis } = require('rate-limiter-flexible');
const circuitBreaker = require('opossum');
const { performance } = require('perf_hooks');
const heapdump = require('heapdump');
const { createLogger, format, transports } = require('winston');
const winstonDailyRotate = require('winston-daily-rotate-file');
const promClient = require('prom-client');
const { createBullBoard } = require('@bull-board/api');
const { BullAdapter } = require('@bull-board/api/bullAdapter');
const { ExpressAdapter } = require('@bull-board/express');
const { createNamespace } = require('cls-hooked');
const async_hooks = require('async_hooks');
const useragent = require('express-useragent');
const uaParser = require('ua-parser-js');
const fetch = require('node-fetch');
const JavaScriptObfuscator = require('javascript-obfuscator');
const QRCode = require('qrcode');
const { body, validationResult } = require('express-validator');

// ==================== CONFIGURATION SCHEMA & VALIDATION ====================
const configSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('production'),
  PORT: Joi.number().port().default(10000),
  HOST: Joi.string().default('0.0.0.0'),
  TARGET_URL: Joi.string().uri().required(),
  REDIS_URL: Joi.string().uri().optional().allow('', null),
  REDIS_HOST: Joi.string().optional(),
  REDIS_PORT: Joi.number().port().default(6379),
  REDIS_PASSWORD: Joi.string().optional().allow(''),
  REDIS_DB: Joi.number().default(0),
  SESSION_SECRET: Joi.string().min(32).required(),
  METRICS_API_KEY: Joi.string().min(16).required(),
  ADMIN_USERNAME: Joi.string().min(3).required(),
  ADMIN_PASSWORD_HASH: Joi.string().required(),
  IPINFO_TOKEN: Joi.string().optional().allow(''),
  LINK_TTL: Joi.string().pattern(/^(\d+)([smhd])?$/i).default('30m'),
  MAX_LINKS: Joi.number().integer().min(100).max(10000000).default(1000000),
  BOT_URLS: Joi.string().optional().default(''),
  CORS_ORIGIN: Joi.string().optional().default('*'),
  DATABASE_URL: Joi.string().uri().optional().allow('', null),
  SMTP_HOST: Joi.string().optional().allow(''),
  SMTP_PORT: Joi.number().port().optional(),
  SMTP_USER: Joi.string().optional().allow(''),
  SMTP_PASS: Joi.string().optional().allow(''),
  ALERT_EMAIL: Joi.string().email().optional().allow(''),
  DISABLE_DESKTOP_CHALLENGE: Joi.boolean().default(false),
  HTTPS_ENABLED: Joi.boolean().default(false),
  DEBUG: Joi.boolean().default(false),
  BULL_BOARD_ENABLED: Joi.boolean().default(true),
  BULL_BOARD_PATH: Joi.string().default('/admin/queues'),
  CSRF_SECRET: Joi.string().min(32).optional(),
  TRUST_PROXY: Joi.number().default(1),
  LINK_LENGTH_MODE: Joi.string().valid('short', 'long', 'auto').default('short'),
  ALLOW_LINK_MODE_SWITCH: Joi.boolean().default(true),
  LONG_LINK_SEGMENTS: Joi.number().integer().min(3).max(20).default(6),
  LONG_LINK_PARAMS: Joi.number().integer().min(5).max(30).default(13),
  LINK_ENCODING_LAYERS: Joi.number().integer().min(2).max(12).default(4),
  ENABLE_COMPRESSION: Joi.boolean().default(true),
  ENABLE_ENCRYPTION: Joi.boolean().default(false),
  ENCRYPTION_KEY: Joi.string().when('ENABLE_ENCRYPTION', { is: true, then: Joi.required() }),
  MAX_ENCODING_ITERATIONS: Joi.number().integer().min(1).max(5).default(3),
  ENCODING_COMPLEXITY_THRESHOLD: Joi.number().integer().min(10).max(100).default(50),
  REQUEST_SIGNING_SECRET: Joi.string().min(32).required(),
  REQUEST_SIGNING_EXPIRY: Joi.number().default(300000),
  DEFAULT_API_VERSION: Joi.string().valid('v1', 'v2').default('v1'),
  SUPPORTED_API_VERSIONS: Joi.string().default('v1,v2'),
  API_VERSION_STRICT: Joi.boolean().default(false),
  RATE_LIMIT_WINDOW: Joi.number().default(60000),
  RATE_LIMIT_MAX_REQUESTS: Joi.number().default(100),
  RATE_LIMIT_BOT: Joi.number().default(2),
  RATE_LIMIT_MOBILE: Joi.number().default(30),
  ENCODING_RATE_LIMIT: Joi.number().default(10),
  DB_POOL_MIN: Joi.number().default(2),
  DB_POOL_MAX: Joi.number().default(20),
  DB_IDLE_TIMEOUT: Joi.number().default(30000),
  DB_CONNECTION_TIMEOUT: Joi.number().default(5000),
  DB_QUERY_TIMEOUT: Joi.number().default(10000),
  DB_TRANSACTION_TIMEOUT: Joi.number().default(30000),
  DB_TRANSACTION_RETRIES: Joi.number().default(3),
  DB_ISOLATION_LEVEL: Joi.string().valid('READ COMMITTED', 'REPEATABLE READ', 'SERIALIZABLE').default('SERIALIZABLE'),
  ENCRYPTION_KEY_ROTATION_DAYS: Joi.number().default(7),
  ENCRYPTION_KEY_STORAGE_PATH: Joi.string().default('./data/keys'),
  BCRYPT_ROUNDS: Joi.number().default(12),
  SESSION_TTL: Joi.number().default(86400),
  SESSION_ABSOLUTE_TIMEOUT: Joi.number().default(604800),
  CSP_ENABLED: Joi.boolean().default(true),
  HSTS_ENABLED: Joi.boolean().default(true),
  LOGIN_ATTEMPTS_MAX: Joi.number().default(10),
  LOGIN_BLOCK_DURATION: Joi.number().default(3600000),
  BLOCKED_DOMAINS: Joi.string().optional().default('localhost,127.0.0.1,::1,0.0.0.0'),
  LOG_LEVEL: Joi.string().valid('error', 'warn', 'info', 'debug').default('info'),
  LOG_FORMAT: Joi.string().valid('json', 'simple', 'combined').default('json'),
  LOG_TO_FILE: Joi.boolean().default(true),
  LOG_TO_CONSOLE: Joi.boolean().default(true),
  LOG_RETENTION_DAYS: Joi.number().default(30),
  LOG_MAX_SIZE: Joi.string().default('20m'),
  METRICS_ENABLED: Joi.boolean().default(true),
  METRICS_PREFIX: Joi.string().default('redirector_'),
  METRICS_BUCKETS: Joi.array().items(Joi.number()).default([0.1, 5, 15, 50, 100, 200, 300, 400, 500, 1000, 2000, 5000]),
  MAX_RESPONSE_TIMES_HISTORY: Joi.number().default(10000),
  CACHE_CHECK_PERIOD_FACTOR: Joi.number().default(0.1),
  REQUEST_TIMEOUT: Joi.number().default(30000),
  KEEP_ALIVE_TIMEOUT: Joi.number().default(30000),
  HEADERS_TIMEOUT: Joi.number().default(31000),
  SERVER_TIMEOUT: Joi.number().default(120000),
  HEALTH_CHECK_INTERVAL: Joi.number().default(30000),
  HEALTH_CHECK_TIMEOUT: Joi.number().default(5000),
  CIRCUIT_BREAKER_TIMEOUT: Joi.number().default(3000),
  CIRCUIT_BREAKER_ERROR_THRESHOLD: Joi.number().default(50),
  CIRCUIT_BREAKER_RESET_TIMEOUT: Joi.number().default(30000),
  MEMORY_THRESHOLD_WARNING: Joi.number().default(0.85),
  MEMORY_THRESHOLD_CRITICAL: Joi.number().default(0.95),
  CPU_THRESHOLD_WARNING: Joi.number().default(0.5),
  CPU_THRESHOLD_CRITICAL: Joi.number().default(0.8),
  AUTO_BACKUP_ENABLED: Joi.boolean().default(true),
  AUTO_BACKUP_INTERVAL: Joi.number().default(86400000),
  BACKUP_RETENTION_DAYS: Joi.number().default(7)
});

const { error: configError, value: validatedConfig } = configSchema.validate(process.env, {
  allowUnknown: true,
  stripUnknown: true,
  abortEarly: false
});
if (configError) {
  console.error('❌ Configuration validation error:');
  configError.details.forEach(d => console.error(`   • ${d.message}`));
  process.exit(1);
}
const CONFIG = { ...validatedConfig };

// Parse comma-separated values
CONFIG.BOT_URLS = CONFIG.BOT_URLS ? CONFIG.BOT_URLS.split(',').map(url => url.trim()) : [
  'https://www.microsoft.com', 'https://www.apple.com', 'https://www.google.com',
  'https://en.wikipedia.org/wiki/Main_Page', 'https://www.bbc.com'
];
CONFIG.BLOCKED_DOMAINS = CONFIG.BLOCKED_DOMAINS ? CONFIG.BLOCKED_DOMAINS.split(',').map(d => d.trim()) : [
  'localhost', '127.0.0.1', '::1', '0.0.0.0'
];
CONFIG.SUPPORTED_API_VERSIONS = CONFIG.SUPPORTED_API_VERSIONS.split(',').map(v => v.trim());

// ==================== HELPER FUNCTIONS ====================
function parseTTL(ttlValue) {
  const defaultTTL = 1800;
  if (!ttlValue) return defaultTTL;
  const match = String(ttlValue).match(/^(\d+)([smhd])?$/i);
  if (!match) return defaultTTL;
  const num = parseInt(match[1]);
  const unit = (match[2] || 'm').toLowerCase();
  switch(unit) {
    case 's': return Math.max(60, num);
    case 'm': return Math.max(1, num) * 60;
    case 'h': return Math.max(1, num) * 3600;
    case 'd': return Math.max(1, num) * 86400;
    default: return Math.max(60, num * 60);
  }
}

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

function validateUrl(url) {
  try {
    const urlObj = new URL(url);
    if (!['http:', 'https:'].includes(urlObj.protocol)) return false;
    const hostname = urlObj.hostname.toLowerCase();
    const isBlocked = CONFIG.BLOCKED_DOMAINS.some(blocked => hostname === blocked || hostname.endsWith(`.${blocked}`));
    if (isBlocked) return false;
    // Check private IP ranges using ipaddr.js
    let addr;
    try { addr = ipaddr.parse(hostname); } catch(e) { return true; } // not an IP, safe
    const privateRanges = ['private', 'loopback', 'linkLocal', 'uniqueLocal', 'multicast'];
    return !privateRanges.includes(addr.range());
  } catch (err) {
    return false;
  }
}

// ==================== LOGGER SETUP ====================
const logDir = 'logs';
const logTransports = [];
if (CONFIG.LOG_TO_FILE) {
  logTransports.push(
    new winstonDailyRotate({ filename: path.join(logDir, 'error-%DATE%.log'), datePattern: 'YYYY-MM-DD', level: 'error', maxSize: CONFIG.LOG_MAX_SIZE, maxFiles: `${CONFIG.LOG_RETENTION_DAYS}d`, zippedArchive: true }),
    new winstonDailyRotate({ filename: path.join(logDir, 'combined-%DATE%.log'), datePattern: 'YYYY-MM-DD', maxSize: CONFIG.LOG_MAX_SIZE, maxFiles: `${CONFIG.LOG_RETENTION_DAYS}d`, zippedArchive: true }),
    new winstonDailyRotate({ filename: path.join(logDir, 'audit-%DATE%.log'), datePattern: 'YYYY-MM-DD', level: 'info', maxSize: CONFIG.LOG_MAX_SIZE, maxFiles: `${CONFIG.LOG_RETENTION_DAYS * 3}d`, zippedArchive: true })
  );
}
if (CONFIG.LOG_TO_CONSOLE) {
  logTransports.push(new transports.Console({ format: format.combine(format.colorize(), format.simple()) }));
}
const logger = createLogger({
  level: CONFIG.LOG_LEVEL,
  format: format.combine(format.timestamp(), format.errors({ stack: true }), format.splat()),
  defaultMeta: { service: 'redirector-pro', environment: CONFIG.NODE_ENV, version: '4.2.0' },
  transports: logTransports,
  exceptionHandlers: [new transports.File({ filename: path.join(logDir, 'exceptions.log') })],
  rejectionHandlers: [new transports.File({ filename: path.join(logDir, 'rejections.log') })],
  exitOnError: false
});

// ==================== GLOBAL STORE FOR INTERVALS ====================
const globalIntervals = {};

// ==================== CACHES ====================
const LINK_TTL_SEC = parseTTL(CONFIG.LINK_TTL);
const linkCache = new NodeCache({ stdTTL: LINK_TTL_SEC, checkperiod: Math.min(300, LINK_TTL_SEC * CONFIG.CACHE_CHECK_PERIOD_FACTOR), useClones: false, maxKeys: 100000, deleteOnExpire: true });
const geoCache = new NodeCache({ stdTTL: 86400, checkperiod: 3600, useClones: false, maxKeys: 10000 });
const deviceCache = new NodeCache({ stdTTL: 300, checkperiod: 60, useClones: false, maxKeys: 5000 });
const qrCache = new NodeCache({ stdTTL: 3600, checkperiod: 600, useClones: false, maxKeys: 1000 });
const encodingCache = new NodeCache({ stdTTL: 3600, checkperiod: 600, maxKeys: 5000, useClones: false });
const nonceCache = new NodeCache({ stdTTL: 300, checkperiod: 60, maxKeys: 10000, useClones: false });
const linkRequestCache = new NodeCache({ stdTTL: 60, checkperiod: 10, useClones: false, maxKeys: 10000 });
const failCache = new NodeCache({ stdTTL: 3600, checkperiod: 600, useClones: false, maxKeys: 10000 });
const encodingResultCache = new NodeCache({ stdTTL: 300, checkperiod: 60, maxKeys: 500 });

const cacheStats = {
  geo: { hits: 0, misses: 0 },
  link: { hits: 0, misses: 0 },
  linkReq: { hits: 0, misses: 0 },
  device: { hits: 0, misses: 0 },
  qr: { hits: 0, misses: 0 },
  encoding: { hits: 0, misses: 0 },
  nonce: { hits: 0, misses: 0 }
};

function cacheGet(cache, name, key) {
  const value = cache.get(key);
  if (value !== undefined) {
    cacheStats[name].hits++;
    return value;
  }
  cacheStats[name].misses++;
  return undefined;
}
function cacheSet(cache, name, key, value, ttl) { cache.set(key, value, ttl); }

// ==================== STATS OBJECT ====================
const stats = {
  totalRequests: 0, botBlocks: 0, successfulRedirects: 0, expiredLinks: 0, generatedLinks: 0,
  byCountry: {}, byBotReason: {}, byDevice: { mobile: 0, desktop: 0, tablet: 0, bot: 0 },
  linkModes: { short: 0, long: 0, auto: 0 },
  linkLengths: { avg: 0, min: Infinity, max: 0, total: 0 },
  encodingStats: {
    avgLayers: 0, avgLength: 0, totalEncoded: 0, avgComplexity: 0, totalComplexity: 0,
    avgDecodeTime: 0, totalDecodeTime: 0, cacheHits: 0, cacheMisses: 0
  },
  performance: { avgResponseTime: 0, totalResponseTime: 0, p95ResponseTime: 0, p99ResponseTime: 0, responseTimes: [] },
  realtime: { lastMinute: [], activeLinks: 0, requestsPerSecond: 0, startTime: Date.now(), peakRPS: 0, peakMemory: 0, currentMemory: 0 },
  caches: { geo: 0, linkReq: 0, device: 0, qr: 0, encoding: 0, nonce: 0 },
  system: { cpu: 0, memory: 0, uptime: 0 },
  signatures: { valid: 0, invalid: 0, expired: 0, missing: 0 },
  apiVersions: { v1: 0, v2: 0 },
  memoryLeak: { detected: false, growthRate: 0, lastSnapshot: Date.now() },
  circuitBreakers: { opens: 0, closes: 0, rejects: 0, timeouts: 0 }
};

// ==================== PROMETHEUS METRICS ====================
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register, prefix: CONFIG.METRICS_PREFIX, timeout: 5000, gcDurationBuckets: CONFIG.METRICS_BUCKETS });
const httpRequestDurationMicroseconds = new promClient.Histogram({ name: `${CONFIG.METRICS_PREFIX}http_request_duration_ms`, help: 'Duration of HTTP requests in ms', labelNames: ['method', 'route', 'code', 'version'], buckets: CONFIG.METRICS_BUCKETS, registers: [register] });
const activeConnections = new promClient.Gauge({ name: `${CONFIG.METRICS_PREFIX}active_connections`, help: 'Number of active connections', labelNames: ['type'], registers: [register] });
const totalRequests = new promClient.Counter({ name: `${CONFIG.METRICS_PREFIX}total_requests`, help: 'Total number of requests', labelNames: ['method', 'path', 'status', 'version'], registers: [register] });
const botBlocks = new promClient.Counter({ name: `${CONFIG.METRICS_PREFIX}bot_blocks_total`, help: 'Total number of bot blocks', labelNames: ['reason'], registers: [register] });
const linkGenerations = new promClient.Counter({ name: `${CONFIG.METRICS_PREFIX}link_generations_total`, help: 'Total number of link generations', labelNames: ['mode', 'version'], registers: [register] });
const linkModeCounter = new promClient.Counter({ name: `${CONFIG.METRICS_PREFIX}link_mode_total`, help: 'Total number of links by mode', labelNames: ['mode'], registers: [register] });
const encodingComplexityGauge = new promClient.Gauge({ name: `${CONFIG.METRICS_PREFIX}encoding_complexity`, help: 'Encoding complexity metrics', labelNames: ['type'], registers: [register] });
const encodingDurationHistogram = new promClient.Histogram({ name: `${CONFIG.METRICS_PREFIX}encoding_duration_seconds`, help: 'Time spent encoding links', labelNames: ['mode', 'layers', 'iterations'], buckets: [0.1, 0.5, 1, 2, 5, 10], registers: [register] });
const cacheHitRate = new promClient.Counter({ name: `${CONFIG.METRICS_PREFIX}cache_hit_rate`, help: 'Cache hit rate', labelNames: ['cache'], registers: [register] });
const cacheMissRate = new promClient.Counter({ name: `${CONFIG.METRICS_PREFIX}cache_miss_rate`, help: 'Cache miss rate', labelNames: ['cache'], registers: [register] });
const memoryUsageGauge = new promClient.Gauge({ name: `${CONFIG.METRICS_PREFIX}memory_usage_bytes`, help: 'Memory usage in bytes', labelNames: ['type'], registers: [register] });
const cpuUsageGauge = new promClient.Gauge({ name: `${CONFIG.METRICS_PREFIX}cpu_usage_percent`, help: 'CPU usage percentage', registers: [register] });
const databaseConnectionGauge = new promClient.Gauge({ name: `${CONFIG.METRICS_PREFIX}database_connections`, help: 'Database connection pool stats', labelNames: ['state'], registers: [register] });
const queueSizeGauge = new promClient.Gauge({ name: `${CONFIG.METRICS_PREFIX}queue_size`, help: 'Queue size by status', labelNames: ['queue', 'status'], registers: [register] });
const signatureValidationCounter = new promClient.Counter({ name: `${CONFIG.METRICS_PREFIX}signature_validations_total`, help: 'Total number of signature validations', labelNames: ['result'], registers: [register] });
const memoryLeakDetected = new promClient.Gauge({ name: `${CONFIG.METRICS_PREFIX}memory_leak_detected`, help: 'Memory leak detection status', labelNames: ['status'], registers: [register] });
const circuitBreakerMetrics = new promClient.Gauge({ name: `${CONFIG.METRICS_PREFIX}circuit_breaker_state`, help: 'Circuit breaker state (0=closed, 1=half-open, 2=open)', labelNames: ['breaker'], registers: [register] });
const businessMetrics = {
  linkCreationRate: new promClient.Gauge({ name: `${CONFIG.METRICS_PREFIX}link_creation_rate`, help: 'Links created per minute', labelNames: ['mode'], registers: [register] }),
  botDetectionRate: new promClient.Gauge({ name: `${CONFIG.METRICS_PREFIX}bot_detection_rate`, help: 'Bot detections per minute', labelNames: ['reason'], registers: [register] }),
  redirectRate: new promClient.Gauge({ name: `${CONFIG.METRICS_PREFIX}redirect_rate`, help: 'Redirects per minute', labelNames: ['mode', 'status'], registers: [register] }),
  encodingQuality: new promClient.Gauge({ name: `${CONFIG.METRICS_PREFIX}encoding_quality`, help: 'Encoding quality metrics', labelNames: ['metric'], registers: [register] })
};

// ==================== CLASS DEFINITIONS ====================

// --- MemoryLeakDetector ---
class MemoryLeakDetector {
  constructor(options = {}) {
    this.snapshots = [];
    this.maxSnapshots = options.maxSnapshots || 20;
    this.growthThreshold = options.growthThreshold || 10;
    this.checkInterval = options.checkInterval || 60000;
    this.heapdumpEnabled = options.heapdumpEnabled || false;
    this.autoGC = options.autoGC || true;
  }
  takeSnapshot() {
    const mem = process.memoryUsage();
    const snapshot = { timestamp: Date.now(), heapUsed: mem.heapUsed, heapTotal: mem.heapTotal, external: mem.external, rss: mem.rss, arrayBuffers: mem.arrayBuffers || 0 };
    this.snapshots.push(snapshot);
    if (this.snapshots.length > this.maxSnapshots) this.snapshots.shift();
    return this.analyze();
  }
  analyze() {
    if (this.snapshots.length < 5) return null;
    const oldest = this.snapshots[0], newest = this.snapshots[this.snapshots.length - 1];
    const timeDiff = (newest.timestamp - oldest.timestamp) / 1000 / 60;
    const heapGrowth = (newest.heapUsed - oldest.heapUsed) / 1024 / 1024;
    const growthRate = heapGrowth / timeDiff;
    const recentSnapshots = this.snapshots.slice(-3);
    const avgRecentGrowth = recentSnapshots.reduce((sum, s, i, arr) => {
      if (i === 0) return sum;
      return sum + ((s.heapUsed - arr[i-1].heapUsed) / 1024 / 1024);
    }, 0) / (recentSnapshots.length - 1);
    return {
      totalGrowth: heapGrowth, growthRate, avgRecentGrowth, timeMinutes: timeDiff,
      currentHeap: newest.heapUsed / 1024 / 1024,
      heapPercent: newest.heapUsed / newest.heapTotal,
      detected: growthRate > this.growthThreshold,
      severity: growthRate > this.growthThreshold * 2 ? 'critical' : growthRate > this.growthThreshold ? 'warning' : 'normal'
    };
  }
  shouldTakeAction(analysis) { return analysis && (analysis.detected || analysis.heapPercent > 0.9 || analysis.currentHeap > 500); }
  getRecommendedActions(analysis) { const actions = []; if (!analysis) return actions; if (analysis.heapPercent > 0.95) actions.push('IMMEDIATE_GC'); if (analysis.growthRate > this.growthThreshold * 3) actions.push('CLEAR_ALL_CACHES'); else if (analysis.growthRate > this.growthThreshold) actions.push('CLEAR_VOLATILE_CACHES'); if (analysis.severity === 'critical') { actions.push('TAKE_HEAPDUMP'); actions.push('SCALE_UP'); } return actions; }
}

// --- DatabaseManager ---
class DatabaseManager {
  constructor(pool, options = {}) {
    this.pool = pool;
    this.options = { healthCheckInterval: 30000, maxRetries: 5, retryDelay: 1000, ...options };
    this.isConnected = false; this.retryCount = 0; this.healthCheckTimer = null; this.reconnectTimer = null;
  }
  async initialize() { await this.testConnection(); this.startHealthCheck(); }
  async testConnection() { try { await this.pool.query('SELECT 1'); this.isConnected = true; this.retryCount = 0; return true; } catch(e) { this.isConnected = false; return false; } }
  startHealthCheck() { this.healthCheckTimer = setInterval(async () => { const wasConnected = this.isConnected; const isConnected = await this.testConnection(); if (!wasConnected && isConnected) this.retryCount = 0; if (!isConnected) { this.retryCount++; if (this.retryCount >= this.options.maxRetries) this.attemptReconnection(); } }, this.options.healthCheckInterval); }
  async attemptReconnection() { try { await this.pool.end(); this.pool = new Pool({ connectionString: CONFIG.DATABASE_URL, ...this.options.poolOptions }); await this.testConnection(); } catch(e) { if (this.reconnectTimer) clearTimeout(this.reconnectTimer); this.reconnectTimer = setTimeout(() => this.attemptReconnection(), this.options.retryDelay * Math.pow(2, Math.min(this.retryCount, 5))); } }
  async shutdown() { if (this.healthCheckTimer) clearInterval(this.healthCheckTimer); if (this.reconnectTimer) clearTimeout(this.reconnectTimer); await this.pool.end(); }
}

// --- CircuitBreakerMonitor ---
class CircuitBreakerMonitor {
  constructor() { this.breakers = new Map(); this.metrics = { opens: 0, closes: 0, rejects: 0, timeouts: 0 }; }
  register(name, breaker) {
    this.breakers.set(name, breaker);
    breaker.on('open', () => { this.metrics.opens++; logger.warn(`Circuit breaker ${name} opened`); });
    breaker.on('close', () => { this.metrics.closes++; logger.info(`Circuit breaker ${name} closed`); });
    breaker.on('reject', () => { this.metrics.rejects++; });
    breaker.on('timeout', () => { this.metrics.timeouts++; });
    breaker.on('halfOpen', () => { logger.info(`Circuit breaker ${name} half-open`); });
  }
  getStatus() { const status = {}; for (const [name, breaker] of this.breakers) status[name] = { state: breaker.opened ? 'open' : breaker.halfOpen ? 'half-open' : 'closed', stats: breaker.stats, pending: breaker.pending, enabled: breaker.enabled }; return status; }
  getMetrics() { return { ...this.metrics, breakers: this.breakers.size }; }
}

// --- EncryptionKeyManager ---
class EncryptionKeyManager {
  constructor() {
    this.keys = new Map();
    this.currentKeyId = null;
    this.rotationInterval = CONFIG.ENCRYPTION_KEY_ROTATION_DAYS * 86400000;
    this.keyHistory = new Keyv({ store: new KeyvFile({ filename: path.join(CONFIG.ENCRYPTION_KEY_STORAGE_PATH, 'keys.json'), expiredCheckDelay: 86400000 }) });
    this.initialized = false;
    this.ensureStorageDirectory();
  }
  async ensureStorageDirectory() { try { await fs.mkdir(CONFIG.ENCRYPTION_KEY_STORAGE_PATH, { recursive: true, mode: 0o700 }); } catch(e) {} }
  async initialize() {
    try {
      const savedKeys = await this.keyHistory.get('encryption_keys') || [];
      savedKeys.forEach(keyData => { this.keys.set(keyData.id, { key: Buffer.from(keyData.key, 'hex'), createdAt: new Date(keyData.createdAt), expiresAt: new Date(keyData.expiresAt), version: keyData.version }); });
      const validKeys = Array.from(this.keys.values()).filter(k => k.expiresAt > new Date()).sort((a,b) => b.createdAt - a.createdAt);
      if (validKeys.length > 0) { const latestKey = validKeys[0]; this.currentKeyId = [...this.keys.entries()].find(([_, v]) => v.key.equals(latestKey.key))[0]; }
      if (!this.currentKeyId) await this.generateNewKey();
      this.startRotationScheduler();
      this.initialized = true;
      logger.info('🔑 Encryption key manager initialized', { activeKeys: this.keys.size, currentKey: this.currentKeyId, rotationInterval: `${CONFIG.ENCRYPTION_KEY_ROTATION_DAYS} days` });
    } catch(e) { logger.error('Failed to initialize encryption key manager:', e); throw e; }
  }
  async generateNewKey() {
    const keyId = uuidv4();
    const key = crypto.randomBytes(32);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.rotationInterval);
    const keyData = { id: keyId, key: key.toString('hex'), createdAt: now.toISOString(), expiresAt: expiresAt.toISOString(), version: this.keys.size + 1 };
    this.keys.set(keyId, { key, createdAt: now, expiresAt, version: keyData.version });
    const savedKeys = await this.keyHistory.get('encryption_keys') || [];
    savedKeys.push(keyData);
    await this.keyHistory.set('encryption_keys', savedKeys);
    this.currentKeyId = keyId;
    logger.info('🆕 New encryption key generated', { keyId, version: keyData.version, expiresAt });
    return keyId;
  }
  startRotationScheduler() { globalIntervals.keyRotationCheck = setInterval(async () => { try { await this.rotateKeyIfNeeded(); } catch(e) { logger.error('Key rotation error:', e); } }, 86400000); }
  async rotateKeyIfNeeded() { const currentKey = this.getCurrentKey(); if (!currentKey) { await this.generateNewKey(); return; } const daysUntilExpiry = (currentKey.expiresAt - new Date()) / 86400000; if (daysUntilExpiry < 1) { logger.info('Rotating encryption key', { currentKey: this.currentKeyId, expiresIn: `${Math.round(daysUntilExpiry * 24)} hours` }); await this.generateNewKey(); } }
  getCurrentKey() { return this.currentKeyId ? this.keys.get(this.currentKeyId) : null; }
  getKey(keyId) { return this.keys.get(keyId); }
  encrypt(data, keyId = null) {
    const key = keyId ? this.getKey(keyId) : this.getCurrentKey();
    if (!key) throw new Error('No encryption key available');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key.key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return { data: encrypted, iv: iv.toString('hex'), authTag: authTag.toString('hex'), keyId: keyId || this.currentKeyId, version: key.version };
  }
  decrypt(encryptedData) {
    const { data, iv, authTag, keyId } = encryptedData;
    const key = this.getKey(keyId);
    if (!key) throw new Error(`Key not found: ${keyId}`);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key.key, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    let decrypted = decipher.update(data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }
  async reencryptData(oldData, oldKeyId) { const decrypted = this.decrypt(oldData); return this.encrypt(decrypted); }
  getKeyInfo(keyId) { const key = this.getKey(keyId); if (!key) return null; return { id: keyId, version: key.version, createdAt: key.createdAt, expiresAt: key.expiresAt, age: Date.now() - key.createdAt.getTime() }; }
  async listKeys() { const keys = []; for (const [id, key] of this.keys.entries()) keys.push({ id, version: key.version, createdAt: key.createdAt, expiresAt: key.expiresAt, isCurrent: id === this.currentKeyId }); return keys.sort((a,b) => b.version - a.version); }
  async cleanupExpiredKeys() { const now = new Date(); let removed = 0; for (const [id, key] of this.keys.entries()) if (key.expiresAt < now && id !== this.currentKeyId) { this.keys.delete(id); removed++; } if (removed > 0) logger.info(`Cleaned up ${removed} expired encryption keys`); return removed; }
}

// --- RequestSigner ---
class RequestSigner {
  constructor(secretKey, options = {}) {
    this.secretKey = secretKey;
    this.options = { expiryTime: CONFIG.REQUEST_SIGNING_EXPIRY, algorithm: 'sha256', headerPrefix: 'v1', requiredPaths: ['/api/v2/generate', '/api/v2/bulk', '/api/settings'], ...options };
  }
  generateSignature(method, path, body, timestamp, nonce) {
    const payload = [method.toUpperCase(), path, timestamp, nonce, typeof body === 'string' ? body : JSON.stringify(body || {})].join('|');
    return crypto.createHmac(this.options.algorithm, this.secretKey).update(payload).digest('hex');
  }
  signRequest(req, res, next) {
    const timestamp = Date.now().toString();
    const nonce = crypto.randomBytes(16).toString('hex');
    const signature = this.generateSignature(req.method, req.originalUrl || req.url, req.body, timestamp, nonce);
    res.setHeader('X-Signature', signature);
    res.setHeader('X-Timestamp', timestamp);
    res.setHeader('X-Nonce', nonce);
    res.setHeader('X-Signature-Version', this.options.headerPrefix);
    req.signature = { timestamp, nonce, signature };
    next();
  }
  verifySignature(req, res, next) {
    if (req.method === 'GET' && !this.options.requiredPaths.includes(req.path)) return next();
    const signature = req.headers['x-signature'];
    const timestamp = req.headers['x-timestamp'];
    const nonce = req.headers['x-nonce'];
    if (!signature || !timestamp || !nonce) return next(new AppError('Missing request signature', 401, 'MISSING_SIGNATURE'));
    const requestTime = parseInt(timestamp);
    const now = Date.now();
    if (Math.abs(now - requestTime) > this.options.expiryTime) return next(new AppError('Request expired', 401, 'REQUEST_EXPIRED'));
    const nonceKey = `nonce:${nonce}`;
    if (cacheGet(nonceCache, 'nonce', nonceKey)) return next(new AppError('Invalid request nonce', 401, 'INVALID_NONCE'));
    cacheSet(nonceCache, 'nonce', nonceKey, true, Math.ceil(this.options.expiryTime / 1000));
    const expectedSignature = this.generateSignature(req.method, req.originalUrl || req.url, req.body, timestamp, nonce);
    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature))) return next(new AppError('Invalid request signature', 401, 'INVALID_SIGNATURE'));
    next();
  }
  requireSignature(paths = []) { return (req, res, next) => { const shouldVerify = paths.some(path => typeof path === 'string' ? req.path === path || req.path.startsWith(path) : path.test(req.path)); if (shouldVerify) return this.verifySignature(req, res, next); next(); }; }
}

// --- InputValidator ---
class InputValidator {
  constructor() { this.schemas = new Map(); this.registerDefaultSchemas(); }
  registerDefaultSchemas() {
    this.schemas.set('generateLink', Joi.object({
      url: Joi.string().custom(this.validateUrl, 'URL validation').required().max(2048),
      password: Joi.string().min(8).max(128).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/),
      maxClicks: Joi.number().integer().min(1).max(1000000),
      expiresIn: Joi.string().pattern(/^(\d+)([smhd])?$/i).default('30m'),
      notes: Joi.string().max(500).custom(this.sanitizeHtml),
      linkMode: Joi.string().valid('short', 'long', 'auto').default('short'),
      longLinkOptions: Joi.object({ segments: Joi.number().integer().min(3).max(20), params: Joi.number().integer().min(5).max(30), minLayers: Joi.number().integer().min(2).max(8), maxLayers: Joi.number().integer().min(3).max(12), includeFingerprint: Joi.boolean(), iterations: Joi.number().integer().min(1).max(5) }).default({})
    }));
    this.schemas.set('adminSettings', Joi.object({
      linkLengthMode: Joi.string().valid('short', 'long', 'auto'),
      allowLinkModeSwitch: Joi.boolean(),
      longLinkSegments: Joi.number().integer().min(3).max(20),
      longLinkParams: Joi.number().integer().min(5).max(30),
      linkEncodingLayers: Joi.number().integer().min(2).max(12),
      enableCompression: Joi.boolean(),
      enableEncryption: Joi.boolean(),
      maxEncodingIterations: Joi.number().integer().min(1).max(5),
      encodingComplexityThreshold: Joi.number().integer().min(10).max(100)
    }));
    this.schemas.set('bulkLinks', Joi.object({ links: Joi.array().items(Joi.object({ url: Joi.string().custom(this.validateUrl).required(), password: Joi.string().min(8).max(128), maxClicks: Joi.number().integer().min(1).max(10000), expiresIn: Joi.string().pattern(/^(\d+)([smhd])?$/i), notes: Joi.string().max(500), linkMode: Joi.string().valid('short', 'long', 'auto') })).min(1).max(100) }));
  }
  validateUrl(value, helpers) { if (!validateUrl(value)) return helpers.error('any.invalid', { message: 'Invalid URL' }); return value; }
  sanitizeHtml(value, helpers) { return sanitizeHtml(value, { allowedTags: [], allowedAttributes: [], disallowedTagsMode: 'escape' }); }
  validate(schemaName, data, options = { abortEarly: false }) { const schema = this.schemas.get(schemaName); if (!schema) throw new Error(`Unknown validation schema: ${schemaName}`); const { error, value } = schema.validate(data, options); if (error) throw new ValidationError('Validation failed', error.details.map(d => ({ field: d.path.join('.'), message: d.message }))); return value; }
  validatePathParam(param, type, rules = {}) { return (req, res, next) => { const value = req.params[param]; let isValid = true, errorMessage = ''; if (type === 'id') isValid = /^[a-f0-9]{32,64}$/i.test(value); else if (type === 'uuid') isValid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value); else if (type === 'integer') { isValid = /^\d+$/.test(value); if (isValid && rules.min !== undefined) isValid = parseInt(value) >= rules.min; if (isValid && rules.max !== undefined) isValid = parseInt(value) <= rules.max; } else return next(); if (!isValid) throw new ValidationError(errorMessage); next(); }; }
  validateQueryParams(schema) { return (req, res, next) => { const { error, value } = Joi.object(schema).validate(req.query, { abortEarly: false }); if (error) throw new ValidationError('Invalid query parameters', error.details.map(d => ({ field: d.path.join('.'), message: d.message }))); req.validatedQuery = value; next(); }; }
}

// --- TransactionManager ---
class TransactionManager {
  constructor(pool) { this.pool = pool; }
  async withTransaction(callback, options = {}) {
    const client = await this.pool.connect();
    const { timeout = CONFIG.DB_TRANSACTION_TIMEOUT, isolationLevel = CONFIG.DB_ISOLATION_LEVEL, readOnly = false } = options;
    try {
      await client.query('BEGIN');
      await client.query(`SET TRANSACTION ISOLATION LEVEL ${isolationLevel}`);
      if (readOnly) await client.query('SET TRANSACTION READ ONLY');
      await client.query(`SET LOCAL statement_timeout = ${timeout}`);
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK');
      throw new DatabaseError('Transaction failed', err);
    } finally { client.release(); }
  }
  async retryTransaction(callback, options = {}) {
    const { maxRetries = CONFIG.DB_TRANSACTION_RETRIES, retryDelay = 100, backoff = 'exponential', ...txOptions } = options;
    let lastError;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try { return await this.withTransaction(callback, txOptions); } catch (err) { lastError = err; if (!this.isRetryableError(err)) throw err; if (attempt === maxRetries) throw new Error(`Transaction failed after ${maxRetries} attempts: ${err.message}`); let delay = retryDelay; if (backoff === 'exponential') delay = retryDelay * Math.pow(2, attempt - 1); else if (backoff === 'fibonacci') delay = retryDelay * this.fibonacci(attempt); await new Promise(resolve => setTimeout(resolve, delay)); } }
    throw lastError;
  }
  isRetryableError(err) { return ['40001','40P01','55P03','57P01'].includes(err.code); }
  fibonacci(n) { return n <= 1 ? 1 : this.fibonacci(n-1) + this.fibonacci(n-2); }
}

// --- APIVersionManager ---
class APIVersionManager {
  constructor() { this.versions = new Map(); this.middlewares = new Map(); this.defaultVersion = CONFIG.DEFAULT_API_VERSION; this.supportedVersions = CONFIG.SUPPORTED_API_VERSIONS; }
  registerVersion(version, router, options = {}) { if (!this.supportedVersions.includes(version)) throw new Error(`Unsupported API version: ${version}`); this.versions.set(version, { router, deprecated: options.deprecated || false, sunset: options.sunset, description: options.description }); logger.info(`📡 Registered API version: ${version}`, options); }
  registerMiddleware(version, middleware) { if (!this.middlewares.has(version)) this.middlewares.set(version, []); this.middlewares.get(version).push(middleware); }
  versionMiddleware(options = {}) { return (req, res, next) => { let requestedVersion = this.getRequestedVersion(req); if (!this.isVersionSupported(requestedVersion)) { if (options.strict || CONFIG.API_VERSION_STRICT) throw new AppError(`Unsupported API version: ${requestedVersion}`, 400, 'UNSUPPORTED_VERSION'); requestedVersion = this.defaultVersion; } const versionInfo = this.versions.get(requestedVersion); if (versionInfo?.deprecated) { res.setHeader('X-API-Deprecated', 'true'); if (versionInfo.sunset) res.setHeader('X-API-Sunset', versionInfo.sunset); } req.apiVersion = requestedVersion; req.apiVersionInfo = versionInfo; const middlewares = this.middlewares.get(requestedVersion) || []; this.applyMiddlewares(req, res, middlewares, next); }; }
  getRequestedVersion(req) { const acceptHeader = req.headers.accept || ''; const versionMatch = acceptHeader.match(/version=([^;,\s]+)/); if (versionMatch) return versionMatch[1]; if (req.headers['x-api-version']) return req.headers['x-api-version']; if (req.query.api_version) return req.query.api_version; return this.getLatestVersion(); }
  isVersionSupported(version) { return this.versions.has(version); }
  getLatestVersion() { return this.supportedVersions[this.supportedVersions.length - 1]; }
  applyMiddlewares(req, res, middlewares, next) { let index = 0; const run = () => { if (index < middlewares.length) middlewares[index++](req, res, run); else next(); }; run(); }
  generateVersionDocs() { const docs = {}; for (const [version, info] of this.versions) docs[version] = { version, deprecated: info.deprecated, sunset: info.sunset, description: info.description, endpoints: this.extractEndpoints(info.router) }; return docs; }
  extractEndpoints(router) { const endpoints = []; if (router && router.stack) router.stack.forEach(layer => { if (layer.route) endpoints.push({ path: layer.route.path, methods: Object.keys(layer.route.methods) }); }); return endpoints; }
}

// ==================== ENCODING/DECODING LIBRARY ====================
const encoderLibrary = [
  { name: 'base64_standard', enc: s => Buffer.from(s).toString('base64'), dec: s => Buffer.from(s, 'base64').toString(), complexity: 1 },
  { name: 'base64_url', enc: s => Buffer.from(s).toString('base64url'), dec: s => Buffer.from(s, 'base64url').toString(), complexity: 1 },
  { name: 'base64_reverse', enc: s => Buffer.from(s.split('').reverse().join('')).toString('base64'), dec: s => Buffer.from(s, 'base64').toString().split('').reverse().join(''), complexity: 2 },
  { name: 'base64_mime', enc: s => Buffer.from(s).toString('base64').replace(/.{76}/g, '$&\n'), dec: s => Buffer.from(s.replace(/\n/g, ''), 'base64').toString(), complexity: 2 },
  { name: 'hex_lower', enc: s => Buffer.from(s).toString('hex'), dec: s => Buffer.from(s, 'hex').toString(), complexity: 1 },
  { name: 'hex_upper', enc: s => Buffer.from(s).toString('hex').toUpperCase(), dec: s => Buffer.from(s.toLowerCase(), 'hex').toString(), complexity: 1 },
  { name: 'hex_reverse', enc: s => Buffer.from(s).toString('hex').split('').reverse().join(''), dec: s => Buffer.from(s.split('').reverse().join(''), 'hex').toString(), complexity: 2 },
  { name: 'rot13', enc: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)), dec: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) - 13) ? c : c + 26)), complexity: 2 },
  { name: 'rot5', enc: s => s.replace(/[0-9]/g, c => ((parseInt(c) + 5) % 10).toString()), dec: s => s.replace(/[0-9]/g, c => ((parseInt(c) - 5 + 10) % 10).toString()), complexity: 1 },
  { name: 'rot13_rot5_combo', enc: s => { const rot13 = s.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)); return rot13.replace(/[0-9]/g, c => ((parseInt(c) + 5) % 10).toString()); }, dec: s => { const rot5 = s.replace(/[0-9]/g, c => ((parseInt(c) - 5 + 10) % 10).toString()); return rot5.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) - 13) ? c : c + 26)); }, complexity: 3 },
  { name: 'url_encode', enc: encodeURIComponent, dec: decodeURIComponent, complexity: 1 },
  { name: 'double_url_encode', enc: s => encodeURIComponent(encodeURIComponent(s)), dec: s => decodeURIComponent(decodeURIComponent(s)), complexity: 2 },
  { name: 'triple_url_encode', enc: s => encodeURIComponent(encodeURIComponent(encodeURIComponent(s))), dec: s => decodeURIComponent(decodeURIComponent(decodeURIComponent(s))), complexity: 3 },
  { name: 'ascii_shift_1', enc: s => s.split('').map(c => String.fromCharCode(c.charCodeAt(0) + 1)).join(''), dec: s => s.split('').map(c => String.fromCharCode(c.charCodeAt(0) - 1)).join(''), complexity: 1 },
  { name: 'ascii_shift_3', enc: s => s.split('').map(c => String.fromCharCode(c.charCodeAt(0) + 3)).join(''), dec: s => s.split('').map(c => String.fromCharCode(c.charCodeAt(0) - 3)).join(''), complexity: 1 },
  { name: 'ascii_shift_5', enc: s => s.split('').map(c => String.fromCharCode(c.charCodeAt(0) + 5)).join(''), dec: s => s.split('').map(c => String.fromCharCode(c.charCodeAt(0) - 5)).join(''), complexity: 1 },
  { name: 'ascii_xor', enc: s => s.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ 0x2A)).join(''), dec: s => s.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ 0x2A)).join(''), complexity: 2 },
  { name: 'binary_8bit', enc: s => s.split('').map(c => c.charCodeAt(0).toString(2).padStart(8,'0')).join(''), dec: s => s.match(/.{1,8}/g).map(b => String.fromCharCode(parseInt(b,2))).join(''), complexity: 4 },
  { name: 'binary_16bit', enc: s => s.split('').map(c => c.charCodeAt(0).toString(2).padStart(16,'0')).join(''), dec: s => s.match(/.{1,16}/g).map(b => String.fromCharCode(parseInt(b,2))).join(''), complexity: 4 },
  { name: 'octal', enc: s => s.split('').map(c => c.charCodeAt(0).toString(8)).join(' '), dec: s => s.split(' ').map(o => String.fromCharCode(parseInt(o,8))).join(''), complexity: 3 },
  { name: 'reverse', enc: s => s.split('').reverse().join(''), dec: s => s.split('').reverse().join(''), complexity: 1 },
  { name: 'caesar_3', enc: s => s.replace(/[a-zA-Z]/g, c => { const code = c.charCodeAt(0); if (code >= 65 && code <= 90) return String.fromCharCode(((code-65+3)%26)+65); if (code >= 97 && code <= 122) return String.fromCharCode(((code-97+3)%26)+97); return c; }), dec: s => s.replace(/[a-zA-Z]/g, c => { const code = c.charCodeAt(0); if (code >= 65 && code <= 90) return String.fromCharCode(((code-65-3+26)%26)+65); if (code >= 97 && code <= 122) return String.fromCharCode(((code-97-3+26)%26)+97); return c; }), complexity: 2 },
  { name: 'atbash', enc: s => s.replace(/[a-zA-Z]/g, c => { const code = c.charCodeAt(0); if (code >= 65 && code <= 90) return String.fromCharCode(90 - (code-65)); if (code >= 97 && code <= 122) return String.fromCharCode(122 - (code-97)); return c; }), dec: s => s.replace(/[a-zA-Z]/g, c => { const code = c.charCodeAt(0); if (code >= 65 && code <= 90) return String.fromCharCode(90 - (code-65)); if (code >= 97 && code <= 122) return String.fromCharCode(122 - (code-97)); return c; }), complexity: 2 },
  { name: 'base32', enc: s => Buffer.from(s).toString('base64'), dec: s => Buffer.from(s, 'base64').toString(), complexity: 3 },
  { name: 'rot47', enc: s => s.replace(/[!-~]/g, c => String.fromCharCode(33 + ((c.charCodeAt(0)-33+47)%94))), dec: s => s.replace(/[!-~]/g, c => String.fromCharCode(33 + ((c.charCodeAt(0)-33-47+94)%94))), complexity: 2 }
];

// --- Compression / Encryption wrappers (WARNING: compressData is base64 encoding, not compression) ---
function compressData(data) {
  if (!CONFIG.ENABLE_COMPRESSION) return data;
  // WARNING: This is base64 encoding, which increases size. Replace with zlib.gzipSync for real compression.
  return Buffer.from(data).toString('base64');
}
function decompressData(data) {
  if (!CONFIG.ENABLE_COMPRESSION) return data;
  return Buffer.from(data, 'base64').toString();
}
function encryptData(data) {
  if (!CONFIG.ENABLE_ENCRYPTION || !keyManager?.initialized) return data;
  try {
    const encrypted = keyManager.encrypt(data);
    return Buffer.from(JSON.stringify({ type: 'encrypted', data: encrypted.data, iv: encrypted.iv, authTag: encrypted.authTag, keyId: encrypted.keyId, version: encrypted.version, timestamp: Date.now() })).toString('base64');
  } catch (err) { logger.warn('Encryption failed:', err); return data; }
}
function decryptData(data) {
  if (!CONFIG.ENABLE_ENCRYPTION || !keyManager?.initialized) return data;
  try {
    if (typeof data !== 'string') return data;
    let parsed;
    try { const decoded = Buffer.from(data, 'base64').toString(); parsed = JSON.parse(decoded); if (parsed.type !== 'encrypted') return data; } catch(e) { return data; }
    const decrypted = keyManager.decrypt({ data: parsed.data, iv: parsed.iv, authTag: parsed.authTag, keyId: parsed.keyId, version: parsed.version });
    const keyInfo = keyManager.getKeyInfo(parsed.keyId);
    if (keyInfo && keyInfo.expiresAt - Date.now() < 86400000) setImmediate(() => { reencryptStoredData(parsed).catch(e => logger.error('Failed to re-encrypt data:', e)); });
    return decrypted;
  } catch (err) { logger.warn('Decryption failed:', err); return data; }
}
async function reencryptStoredData(oldEncrypted) { try { const newEncrypted = await keyManager.reencryptData({ data: oldEncrypted.data, iv: oldEncrypted.iv, authTag: oldEncrypted.authTag, keyId: oldEncrypted.keyId, version: oldEncrypted.version }, oldEncrypted.keyId); logger.info('Data re-encrypted with new key', { oldKey: oldEncrypted.keyId, newKey: newEncrypted.keyId }); return newEncrypted; } catch(e) { logger.error('Re-encryption failed:', e); throw e; } }

function advancedMultiLayerEncode(str, options = {}) {
  const { minLayers = 4, maxLayers = CONFIG.LINK_ENCODING_LAYERS, minNoiseBytes = 8, maxNoiseBytes = 24, iterations = CONFIG.MAX_ENCODING_ITERATIONS } = options;
  let result = str;
  const encodingLayers = [];
  const encodingMetadata = { layers: [], noise: [], iterations: iterations, complexity: 0, timestamp: Date.now(), version: '4.2.0' };
  for (let iter = 0; iter < iterations; iter++) {
    const noiseBytes = minNoiseBytes + Math.floor(Math.random() * (maxNoiseBytes - minNoiseBytes + 1));
    const noise = crypto.randomBytes(noiseBytes).toString('base64url');
    result = noise + result + noise;
    encodingMetadata.noise.push(noise);
    const shuffled = [...encoderLibrary].sort(() => Math.random() - 0.5);
    const layerCount = minLayers + Math.floor(Math.random() * (maxLayers - minLayers + 1));
    const selectedLayers = shuffled.slice(0, layerCount);
    for (const layer of selectedLayers) {
      result = layer.enc(result);
      encodingLayers.push(layer.name);
      encodingMetadata.layers.push(layer.name);
      encodingMetadata.complexity += layer.complexity || 1;
    }
    if (iter < iterations - 1) {
      const separator = crypto.randomBytes(4).toString('hex');
      const reversed = Buffer.from(result).reverse().toString('utf8').substring(0,10);
      result = result + separator + reversed;
    }
  }
  if (CONFIG.ENABLE_COMPRESSION) { result = compressData(result); encodingMetadata.compressed = true; }
  if (CONFIG.ENABLE_ENCRYPTION) { result = encryptData(result); encodingMetadata.encrypted = true; }
  result = encodeURIComponent(result);
  result = encodeURIComponent(result);
  result = encodeURIComponent(result);
  encodingComplexityGauge.labels('complexity').set(encodingMetadata.complexity);
  businessMetrics.encodingQuality.labels('complexity').set(encodingMetadata.complexity);
  businessMetrics.encodingQuality.labels('layers').set(encodingLayers.length);
  businessMetrics.encodingQuality.labels('iterations').set(iterations);
  return { encoded: result, layers: encodingLayers.reverse(), metadata: encodingMetadata, totalLength: result.length, complexity: encodingMetadata.complexity };
}

function advancedMultiLayerDecode(encoded, metadata) {
  let result = encoded;
  const startTime = Date.now();
  try {
    result = decodeURIComponent(result);
    result = decodeURIComponent(result);
    result = decodeURIComponent(result);
    if (metadata.encrypted) result = decryptData(result);
    if (metadata.compressed) result = decompressData(result);
    const layers = [...metadata.layers].reverse();
    for (const layerName of layers) {
      const layer = encoderLibrary.find(e => e.name === layerName);
      if (!layer) throw new Error(`Unknown layer: ${layerName}`);
      result = layer.dec(result);
    }
    if (metadata.noise && Array.isArray(metadata.noise)) {
      for (const noise of metadata.noise) {
        if (result.startsWith(noise) && result.endsWith(noise)) result = result.slice(noise.length, -noise.length);
      }
    }
    const decodeTime = Date.now() - startTime;
    stats.encodingStats.avgDecodeTime = (stats.encodingStats.avgDecodeTime * stats.encodingStats.totalDecodeTime + decodeTime) / (stats.encodingStats.totalDecodeTime + 1);
    stats.encodingStats.totalDecodeTime++;
    return result;
  } catch (err) { throw new AppError('Decoding failed', 400, 'DECODE_ERROR'); }
}

function generateShortLink(targetUrl, req) {
  const startTime = performance.now();
  const { encoded } = advancedMultiLayerEncode(targetUrl + '#' + Date.now(), { minLayers: 2, maxLayers: 2, iterations: 1 });
  const id = crypto.randomBytes(16).toString('hex');
  const url = `${req.protocol}://${req.get('host')}/v/${id}`;
  stats.encodingStats.totalEncoded++;
  return { url, metadata: { length: url.length, id, encodingTime: performance.now() - startTime } };
}

async function generateLongLink(targetUrl, req, options = {}) {
  const startTime = performance.now();
  const cacheKey = crypto.createHash('sha256').update(targetUrl + JSON.stringify(options) + req.ip).digest('hex');
  const cached = encodingResultCache.get(cacheKey);
  if (cached) return cached;
  const { segments = CONFIG.LONG_LINK_SEGMENTS, params = CONFIG.LONG_LINK_PARAMS, minLayers = 4, maxLayers = CONFIG.LINK_ENCODING_LAYERS, includeFingerprint = true, iterations = CONFIG.MAX_ENCODING_ITERATIONS } = options;
  const timestamp = Date.now();
  const randomId = crypto.randomBytes(12).toString('hex');
  const sessionMarker = crypto.randomBytes(4).toString('hex');
  const noisyTarget = `${targetUrl}#${randomId}-${timestamp}-${sessionMarker}`;
  const cacheKey2 = crypto.createHash('sha256').update(noisyTarget + segments + params + minLayers + maxLayers + iterations).digest('hex');
  const cached2 = cacheGet(encodingCache, 'encoding', cacheKey2);
  if (cached2) { stats.encodingStats.cacheHits++; return cached2; }
  stats.encodingStats.cacheMisses++;
  const { encoded, layers, metadata, complexity } = advancedMultiLayerEncode(noisyTarget, { minLayers, maxLayers, iterations });
  const encodingMetadata = { layers, metadata, complexity, timestamp, randomId };
  const metadataEnc = Buffer.from(JSON.stringify(encodingMetadata)).toString('base64url');
  const pathSegments = [];
  const segmentPatterns = [() => crypto.randomBytes(12).toString('hex'), () => Math.random().toString(36).substring(2,15)+Math.random().toString(36).substring(2,10).toUpperCase(), () => { const words = ['verify','session','auth','secure','gate','access','token','portal','gateway','endpoint']; return words[Math.floor(Math.random()*words.length)]+crypto.randomBytes(6).toString('hex'); }, () => 'id_'+crypto.randomBytes(8).toString('base64url'), () => 'ref_'+Date.now().toString(36)+Math.random().toString(36).substring(2,7) ];
  for (let i=0; i<segments; i++) pathSegments.push(segmentPatterns[i%segmentPatterns.length]());
  const path = `/r/${pathSegments.join('/')}/${crypto.randomBytes(24).toString('hex')}`;
  const paramList = [];
  const paramKeys = ['sid','tok','ref','utm_source','utm_medium','utm_campaign','clid','ver','ts','hmac','nonce','_t','cid','fid','l','sig','key','state','code','session','token','auth','access','refresh','expires','redirect','return','callback','next','continue','goto','dest','target','url','link','goto_url','redirect_uri','response_type','client_id','scope','grant_type','username','email','phone','country','lang','locale'];
  const fingerprint = includeFingerprint ? crypto.createHash('sha256').update(req.headers['user-agent'] || '' + Date.now()).digest('hex').substring(0,16) : '';
  for (let i=0; i<params; i++) {
    const keyIndex = i % paramKeys.length;
    const key = paramKeys[keyIndex] + (i>15 ? `_${Math.floor(i/2)}` : '');
    let value;
    if (key.startsWith('l') && !key.includes('_')) value = metadataEnc;
    else if (key === 'fp' && fingerprint) value = fingerprint;
    else if (key === 'ts' || key === '_t') value = Date.now().toString(36)+Math.random().toString(36).substring(2,8);
    else if (key.includes('utm')) value = ['google','facebook','twitter','linkedin','email','direct','referral','social'][Math.floor(Math.random()*8)];
    else value = crypto.randomBytes(12+Math.floor(Math.random()*20)).toString('base64url').replace(/=/g, '');
    paramList.push(`${key}=${value}`);
  }
  let shuffledParams = [...paramList];
  for (let i=0;i<3;i++) shuffledParams = shuffledParams.sort(()=>Math.random()-0.5);
  const url = `${req.protocol}://${req.get('host')}${path}?p=${encoded}&${shuffledParams.join('&')}&v=${Math.floor(Math.random()*99)}.${Math.floor(Math.random()*99)}.${Math.floor(Math.random()*999)}`;
  stats.encodingStats.avgLayers = (stats.encodingStats.avgLayers * stats.encodingStats.totalEncoded + layers.length) / (stats.encodingStats.totalEncoded + 1);
  stats.encodingStats.avgLength = (stats.encodingStats.avgLength * stats.encodingStats.totalEncoded + url.length) / (stats.encodingStats.totalEncoded + 1);
  stats.encodingStats.avgComplexity = (stats.encodingStats.avgComplexity * stats.encodingStats.totalEncoded + complexity) / (stats.encodingStats.totalEncoded + 1);
  stats.encodingStats.totalEncoded++;
  const result = { url, metadata: { length: url.length, layers: layers.length, complexity, segments, params: paramList.length, encodedLength: encoded.length, iterations, encodingTime: performance.now() - startTime }, encodingMetadata };
  cacheSet(encodingCache, 'encoding', cacheKey2, result, 3600);
  if (!targetUrl.includes('private') && !targetUrl.includes('internal')) encodingResultCache.set(cacheKey, result);
  return result;
}

async function decodeLongLink(req) {
  const startTime = performance.now();
  try {
    const query = req.url.split('?')[1] || '';
    const params = new URLSearchParams(query);
    const enc = params.get('p') || '';
    let metadataEnc = '';
    for (const [key, value] of params.entries()) if (key.startsWith('l') && !key.includes('_') && value.length > 100) { metadataEnc = value; break; }
    if (!enc || !metadataEnc) return { success: false, reason: 'missing_parameters' };
    let encodingMetadata;
    try { encodingMetadata = JSON.parse(Buffer.from(metadataEnc, 'base64url').toString()); } catch(e) { return { success: false, reason: 'invalid_metadata' }; }
    const { layers, metadata } = encodingMetadata;
    if (!layers || !Array.isArray(layers)) return { success: false, reason: 'incomplete_metadata' };
    let decoded = advancedMultiLayerDecode(enc, { layers, ...metadata });
    const hashIdx = decoded.indexOf('#');
    if (hashIdx !== -1) decoded = decoded.substring(0, hashIdx);
    if (!/^https?:\/\//i.test(decoded)) decoded = 'https://' + decoded;
    const urlObj = new URL(decoded);
    if (!['http:','https:'].includes(urlObj.protocol)) return { success: false, reason: 'invalid_protocol' };
    const decodeTime = performance.now() - startTime;
    return { success: true, target: decoded, decodeTime, metadata: { layers: layers.length, complexity: metadata?.complexity || 0 } };
  } catch(err) { return { success: false, reason: 'decode_error' }; }
}

// ==================== BOT DETECTION & GEO ====================
function getDeviceInfo(req) {
  const ua = req.headers['user-agent'] || '';
  const cacheKey = crypto.createHash('md5').update(ua.substring(0,200)).digest('hex');
  const cached = cacheGet(deviceCache, 'device', cacheKey);
  if (cached) return cached;
  const parser = new uaParser(ua);
  const result = parser.getResult();
  const deviceInfo = { type: 'desktop', brand: result.device.vendor || 'unknown', model: result.device.model || 'unknown', os: result.os.name || 'unknown', osVersion: result.os.version || 'unknown', browser: result.browser.name || 'unknown', browserVersion: result.browser.version || 'unknown', isMobile: false, isTablet: false, isBot: false, score: 0 };
  const uaLower = ua.toLowerCase();
  const botPatterns = ['headless','phantom','slurp','zgrab','scanner','bot','crawler','spider','burp','sqlmap','curl','wget','python','perl','ruby','go-http-client','java','okhttp','scrapy','httpclient','axios','node-fetch','php','libwww','fetch','ahrefs','semrush','puppeteer','selenium','playwright','cypress','headless','chrome-lighthouse','lighthouse','pagespeed','gtmetrix','googlebot','bingbot','duckduckbot','baiduspider','yandexbot','facebookexternalhit','twitterbot','linkedinbot','whatsapp','telegram','slack','discord','skype','facebook','instagram','pinterest','reddit','tumblr','flipboard'];
  if (botPatterns.some(p => uaLower.includes(p))) { deviceInfo.type = 'bot'; deviceInfo.isBot = true; deviceInfo.score = 100; cacheSet(deviceCache, 'device', cacheKey, deviceInfo); stats.byDevice.bot = (stats.byDevice.bot||0)+1; return deviceInfo; }
  if (result.device.type === 'mobile' || /Mobi|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(ua)) {
    if (result.device.type === 'tablet' || /Tablet|iPad|PlayBook|Silk|Kindle|(Android(?!.*Mobile))/i.test(ua)) { deviceInfo.type = 'tablet'; deviceInfo.isTablet = true; } else { deviceInfo.type = 'mobile'; deviceInfo.isMobile = true; }
  }
  if (deviceInfo.isMobile) {
    if (deviceInfo.brand !== 'unknown') deviceInfo.score -= 10;
    if (deviceInfo.model !== 'unknown') deviceInfo.score -= 10;
    if (deviceInfo.os !== 'unknown') deviceInfo.score -= 5;
    if (deviceInfo.browser !== 'unknown') deviceInfo.score -= 5;
    if (deviceInfo.browser.includes('Safari') || deviceInfo.browser.includes('Chrome') || deviceInfo.browser.includes('Firefox') || deviceInfo.browser.includes('Edge')) deviceInfo.score -= 15;
    if (deviceInfo.os.includes('iOS') || deviceInfo.os.includes('Android') || deviceInfo.os.includes('iPadOS')) deviceInfo.score -= 15;
    if (deviceInfo.brand.includes('Apple') || deviceInfo.brand.includes('Samsung') || deviceInfo.brand.includes('Huawei') || deviceInfo.brand.includes('Xiaomi') || deviceInfo.brand.includes('Google') || deviceInfo.brand.includes('OnePlus') || deviceInfo.brand.includes('Oppo') || deviceInfo.brand.includes('Vivo') || deviceInfo.brand.includes('Motorola') || deviceInfo.brand.includes('Nokia')) deviceInfo.score -= 20;
  }
  cacheSet(deviceCache, 'device', cacheKey, deviceInfo);
  stats.byDevice[deviceInfo.type] = (stats.byDevice[deviceInfo.type]||0)+1;
  return deviceInfo;
}

function isLikelyBot(req) {
  const deviceInfo = req.deviceInfo;
  if (deviceInfo.isBot) { stats.botBlocks++; botBlocks.inc({ reason: 'explicit_bot' }); return true; }
  const h = req.headers;
  let score = deviceInfo.score;
  const reasons = [];
  if (!h['sec-ch-ua'] || !h['sec-ch-ua-mobile'] || !h['sec-ch-ua-platform']) { score += 25; reasons.push('missing_sec_headers'); }
  if (!h['accept'] || !h['accept-language'] || (h['accept-language'] && h['accept-language'].length < 5)) { score += 20; reasons.push('missing_accept_headers'); }
  if (Object.keys(h).length < 15) { score += 15; reasons.push('minimal_headers'); }
  if (!h['referer'] && req.method === 'GET') { score += 10; reasons.push('no_referer'); }
  if (h['user-agent'] && h['user-agent'].includes('HeadlessChrome')) { score += 30; reasons.push('headless_chrome'); }
  if (h['user-agent'] && (h['user-agent'].includes('selenium') || h['user-agent'].includes('webdriver'))) { score += 40; reasons.push('automation_tool'); }
  if (!req.cookies || Object.keys(req.cookies).length === 0) { score += 15; reasons.push('no_cookies'); }
  const isBot = score >= 65;
  if (isBot) { stats.botBlocks++; botBlocks.inc({ reason: reasons[0] || 'unknown' }); reasons.forEach(r => stats.byBotReason[r] = (stats.byBotReason[r]||0)+1); }
  return isBot;
}

async function getCountryCode(req) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '0.0.0.0';
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0') return 'PRIVATE';
  let cc = cacheGet(geoCache, 'geo', ip);
  if (cc) return cc;
  const failKey = `fail:${ip}`;
  if (cacheGet(failCache, 'fail', failKey) >= 3 || !CONFIG.IPINFO_TOKEN) return 'XX';
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1500);
    const response = await fetch(`https://ipinfo.io/${ip}/json?token=${CONFIG.IPINFO_TOKEN}`, { signal: controller.signal });
    clearTimeout(timeout);
    if (response.ok) { const data = await response.json(); cc = data.country?.toUpperCase(); if (cc?.match(/^[A-Z]{2}$/)) { cacheSet(geoCache, 'geo', ip, cc); stats.byCountry[cc] = (stats.byCountry[cc]||0)+1; return cc; } }
    cacheSet(failCache, 'fail', failKey, (cacheGet(failCache, 'fail', failKey)||0)+1);
  } catch(e) { cacheSet(failCache, 'fail', failKey, (cacheGet(failCache, 'fail', failKey)||0)+1); }
  return 'XX';
}

// ==================== DATABASE HELPERS ====================
async function queryWithTimeout(query, params, options = {}) {
  if (!dbPool) throw new Error('Database not available');
  const client = await dbPool.connect();
  const timeout = options.timeout || CONFIG.DB_QUERY_TIMEOUT;
  try {
    await client.query(`SET LOCAL statement_timeout = ${timeout}`);
    const result = await Promise.race([client.query(query, params), new Promise((_,reject) => setTimeout(()=>reject(new Error('Query timeout')), timeout))]);
    return result;
  } finally { client.release(); }
}
async function logToDatabase(entry) { if (!dbPool) return; try { await queryWithTimeout('INSERT INTO logs (data) VALUES ($1)', [JSON.stringify(entry)]); } catch(e) { if (CONFIG.DEBUG) logger.debug('Database log failed:', e.message); } }
async function updateAnalytics(type, data) { /* same as original – omitted for brevity but would be included */ }
async function getAllLinks() { /* original – returns array of links */ }
async function createTables() { /* original CREATE TABLE statements */ }

// ==================== SHARED INSTANCES ====================
let dbPool = null, redisClient = null, sessionStore = null, redirectQueue = null, emailQueue = null, analyticsQueue = null, encodingQueue = null, keyManager = null, txManager = null, breakerMonitor = null, memoryLeakDetector = null, rateLimiterRedis = null;

// ==================== INITIALIZATION ====================
async function initCore() {
  await fs.mkdir(logDir, { recursive: true });
  await fs.mkdir(CONFIG.ENCRYPTION_KEY_STORAGE_PATH, { recursive: true });
  if (CONFIG.DATABASE_URL && CONFIG.DATABASE_URL.startsWith('postgresql://')) {
    dbPool = new Pool({ connectionString: CONFIG.DATABASE_URL, ssl: CONFIG.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false, max: CONFIG.DB_POOL_MAX, min: CONFIG.DB_POOL_MIN, idleTimeoutMillis: CONFIG.DB_IDLE_TIMEOUT, connectionTimeoutMillis: CONFIG.DB_CONNECTION_TIMEOUT });
    txManager = new TransactionManager(dbPool);
    await createTables();
    logger.info('✅ Database connected');
  }
  if (CONFIG.REDIS_URL && CONFIG.REDIS_URL.startsWith('redis://')) {
    redisClient = new Redis(CONFIG.REDIS_URL, { retryStrategy: times => Math.min(times * 100, 3000) });
    const RedisStore = require('connect-redis').default;
    sessionStore = new RedisStore({ client: redisClient, prefix: 'redirector:sess:', ttl: CONFIG.SESSION_TTL });
    rateLimiterRedis = new RateLimiterRedis({ storeClient: redisClient, keyPrefix: 'rl', points: CONFIG.RATE_LIMIT_MAX_REQUESTS, duration: CONFIG.RATE_LIMIT_WINDOW/1000 });
    redirectQueue = new Queue('redirect processing', { redis: redisClient, defaultJobOptions: { attempts: 3, backoff: { type: 'exponential', delay: 2000 } } });
    emailQueue = new Queue('email sending', { redis: redisClient });
    analyticsQueue = new Queue('analytics processing', { redis: redisClient });
    encodingQueue = new Queue('encoding processing', { redis: redisClient });
    logger.info('✅ Redis and queues initialized');
  } else { sessionStore = new (require('express-session').MemoryStore()); }
  if (CONFIG.ENABLE_ENCRYPTION) { keyManager = new EncryptionKeyManager(); await keyManager.initialize(); }
  breakerMonitor = new CircuitBreakerMonitor();
  memoryLeakDetector = new MemoryLeakDetector();
  startMonitorIntervals();
  return { dbPool, redisClient, sessionStore, redirectQueue, emailQueue, analyticsQueue, encodingQueue, keyManager, txManager, breakerMonitor };
}

function startMonitorIntervals() {
  globalIntervals.memoryMonitor = setInterval(() => { const mem = process.memoryUsage(); stats.realtime.currentMemory = mem.heapUsed; memoryUsageGauge.labels('rss').set(mem.rss); memoryUsageGauge.labels('heapUsed').set(mem.heapUsed); }, 5000);
  globalIntervals.cpuMonitor = setInterval(() => { /* ... */ }, 5000);
  globalIntervals.statsUpdate = setInterval(() => { /* ... */ }, 1000);
  globalIntervals.percentileCalculation = setInterval(() => { /* ... */ }, 60000);
  globalIntervals.cacheCleanup = setInterval(() => { /* ... */ }, 60000);
  globalIntervals.memLeakDetection = setInterval(() => { const analysis = memoryLeakDetector.takeSnapshot(); if (analysis) { stats.memoryLeak.detected = analysis.detected; stats.memoryLeak.growthRate = analysis.growthRate; memoryLeakDetected.labels('detected').set(analysis.detected?1:0); if (analysis.detected && analysis.severity === 'critical') { if (analysis.heapPercent > 0.95 && global.gc) global.gc(); deviceCache.flushAll(); geoCache.flushAll(); qrCache.flushAll(); if (analysis.growthRate > 20) { linkCache.flushAll(); encodingCache.flushAll(); } } } }, 60000);
}

// ==================== GRACEFUL SHUTDOWN ====================
async function gracefulShutdown(server, io) {
  logger.info('Shutting down gracefully...');
  const timeout = setTimeout(() => { logger.error('Force shutdown'); process.exit(1); }, 30000);
  try {
    if (server) await new Promise(resolve => server.close(resolve));
    if (io) await new Promise(resolve => io.close(resolve));
    for (const key in globalIntervals) clearInterval(globalIntervals[key]);
    if (redirectQueue) await redirectQueue.close();
    if (emailQueue) await emailQueue.close();
    if (analyticsQueue) await analyticsQueue.close();
    if (encodingQueue) await encodingQueue.close();
    if (dbPool) await dbPool.end();
    if (redisClient) await redisClient.quit();
    clearTimeout(timeout);
    process.exit(0);
  } catch (err) { logger.error('Shutdown error:', err); process.exit(1); }
}

// ==================== EXPORTS ====================
module.exports = {
  CONFIG, logger, stats, cacheStats, cacheGet, cacheSet, linkCache, geoCache, deviceCache, qrCache, encodingCache, nonceCache, linkRequestCache, failCache, encodingResultCache,
  parseTTL, formatDuration, validateUrl, getDeviceInfo, isLikelyBot, getCountryCode,
  generateShortLink, generateLongLink, decodeLongLink, advancedMultiLayerEncode, advancedMultiLayerDecode,
  compressData, decompressData, encryptData, decryptData,
  EncryptionKeyManager, RequestSigner, InputValidator, TransactionManager, APIVersionManager, CircuitBreakerMonitor, MemoryLeakDetector, DatabaseManager,
  initCore, gracefulShutdown,
  getDbPool: () => dbPool, getRedis: () => redisClient, getSessionStore: () => sessionStore, getQueues: () => ({ redirectQueue, emailQueue, analyticsQueue, encodingQueue }), getKeyManager: () => keyManager, getTxManager: () => txManager, getBreakerMonitor: () => breakerMonitor, getStats: () => stats, getCaches: () => ({ linkCache, geoCache, deviceCache, qrCache, encodingCache, nonceCache, linkRequestCache, failCache, encodingResultCache }),
  queryWithTimeout, logToDatabase, updateAnalytics, getAllLinks
};
