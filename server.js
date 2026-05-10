// server.js – Entry point for Redirector Pro
// Initializes core system, creates Express app, mounts routes, and starts HTTP server

require('dotenv').config();
const express = require('express');
const http = require('http');
const os = require('os');
const { performance } = require('perf_hooks');

const { initCore, gracefulShutdown, CONFIG, logger, stats } = require('./core');
const { createServer } = require('./routes');

// ==================== CONSTANTS ====================
const STARTUP_TIMEOUT = 30000; // 30 seconds
const HEALTHCHECK_INTERVAL = 30000; // 30 seconds
const MEMORY_CHECK_INTERVAL = 60000; // 1 minute
const VERSION = '4.3.0';

// ==================== STARTUP BANNER ====================
function printStartupBanner(host, port) {
  const divider = '='.repeat(100);
  const lines = [
    '',
    divider,
    `✅ Redirector Pro v${VERSION} starting on http://${host}:${port}`,
    divider,
    `📚 API Documentation:  http://${host}:${port}/api-docs`,
    `👑 Admin Dashboard:    http://${host}:${port}/admin`,
    `🔗 Redirect Short:     http://${host}:${port}/v/[id]`,
    `🔗 Redirect Long:      http://${host}:${port}/r/[path]`,
    `📊 Health Check:       http://${host}:${port}/health`,
    `📈 Metrics (API key):  http://${host}:${port}/metrics`,
    '',
    `⚙️  Configuration:`,
    `  • Environment:       ${CONFIG.NODE_ENV}`,
    `  • Link Mode:         ${CONFIG.LINK_LENGTH_MODE} (switchable: ${CONFIG.ALLOW_LINK_MODE_SWITCH})`,
    `  • Link TTL:          ${CONFIG.LINK_TTL}`,
    `  • Max Links:         ${CONFIG.MAX_LINKS.toLocaleString()}`,
    `  • Compression:       ${CONFIG.ENABLE_COMPRESSION ? '✓ Enabled' : '✗ Disabled'}`,
    `  • Encryption:        ${CONFIG.ENABLE_ENCRYPTION ? '✓ Enabled' : '✗ Disabled'}`,
    `  • Request Signing:   ✓ Enabled (v2 API)`,
    `  • CSRF Protection:   ✓ Enabled`,
    `  • Rate Limiting:     ${CONFIG.RATE_LIMIT_MAX_REQUESTS} req/${CONFIG.RATE_LIMIT_WINDOW}ms`,
    `  • Bot Detection:     ✓ Enabled`,
    '',
    `🔧 Services:`,
    `  • Database:          ${CONFIG.DATABASE_URL ? '✓ Connected' : '✗ Disabled'}`,
    `  • Redis:             ${CONFIG.REDIS_URL ? '✓ Connected' : '✗ Disabled'}`,
    `  • Bull Queues:       ${CONFIG.REDIS_URL ? '✓ Enabled' : '✗ Disabled'}`,
    `  • Session Store:     ${CONFIG.REDIS_URL ? 'Redis' : 'Memory'}`,
    `  • Key Manager:       ${CONFIG.ENABLE_ENCRYPTION ? '✓ Initialized' : '✗ Disabled'}`,
    `  • Bull Board:        ${CONFIG.BULL_BOARD_ENABLED ? `✓ Enabled (${CONFIG.BULL_BOARD_PATH})` : '✗ Disabled'}`,
    '',
    divider,
    `🚀 Server starting with PID: ${process.pid}`,
    `💾 Memory limit: ${Math.round((require('v8').getHeapStatistics().heap_size_limit / 1024 / 1024 / 1024) * 10) / 10} GB`,
    `🔢 Available CPUs: ${os.cpus().length}`,
    divider,
    ''
  ];

  lines.forEach((line) => console.log(line));
}

// ==================== STARTUP SEQUENCE ====================
async function start() {
  const startTime = performance.now();

  try {
    // 1. Initialize core components (database, Redis, queues, encryption, etc.)
    logger.info('🔧 Initializing core components...');
    await initCore();
    logger.info('✅ Core initialization complete');

    // 2. Create Express app
    logger.info('📦 Creating Express application...');
    const app = express();
    const server = http.createServer(app);

    // 3. Configure server timeouts (production-ready)
    logger.info('⏱️  Configuring server timeouts...');
    server.keepAliveTimeout = CONFIG.KEEP_ALIVE_TIMEOUT;
    server.headersTimeout = CONFIG.HEADERS_TIMEOUT;
    server.timeout = CONFIG.SERVER_TIMEOUT;
    server.maxHeadersCount = 1000;
    server.maxConnections = 10000;

    // Set default socket timeout
    server.on('connection', (socket) => {
      socket.setTimeout(CONFIG.KEEP_ALIVE_TIMEOUT);
    });

    // 4. Mount all routes, middleware, and Socket.IO
    logger.info('🛣️  Mounting routes and middleware...');
    const { app: configuredApp, io } = createServer(app, server);

    const PORT = CONFIG.PORT;
    const HOST = CONFIG.HOST;

    // 5. Start HTTP server with error handling
    logger.info(`🚀 Starting HTTP server on ${HOST}:${PORT}...`);

    const serverStartPromise = new Promise((resolve, reject) => {
      const timeoutHandle = setTimeout(() => {
        reject(new Error('Server startup timeout'));
      }, STARTUP_TIMEOUT);

      server.listen(PORT, HOST, () => {
        clearTimeout(timeoutHandle);
        const duration = performance.now() - startTime;
        logger.info(`✅ HTTP server listening on http://${HOST}:${PORT}`, {
          duration: Math.round(duration),
          pid: process.pid
        });
        resolve();
      });

      server.on('error', (err) => {
        clearTimeout(timeoutHandle);
        reject(err);
      });
    });

    await serverStartPromise;

    // 6. Print startup banner
    printStartupBanner(HOST, PORT);

    // 7. Set up health checks
    setupHealthChecks(server, io);

    // 8. Set up memory monitoring
    setupMemoryMonitoring();

    // 9. Set up graceful shutdown handlers
    setupGracefulShutdown(server, io);

    logger.info('✅ Server startup complete', {
      version: VERSION,
      env: CONFIG.NODE_ENV,
      uptime: process.uptime()
    });
  } catch (err) {
    const duration = performance.now() - startTime;
    const errorMsg = err?.message || 'Unknown error';

    console.error(`\n❌ Fatal error during startup (after ${Math.round(duration)}ms):`);
    console.error(`   ${errorMsg}\n`);

    logger.error('Fatal startup error', {
      message: errorMsg,
      stack: err?.stack?.substring(0, 500),
      duration: Math.round(duration)
    });

    process.exit(1);
  }
}

// ==================== HEALTH CHECKS ====================
function setupHealthChecks(server, io) {
  let isHealthy = true;
  let lastHealthCheckTime = Date.now();
  let consecutiveFailures = 0;
  const MAX_CONSECUTIVE_FAILURES = 3;

  const performHealthCheck = async () => {
    try {
      const now = Date.now();
      const timeSinceLastCheck = now - lastHealthCheckTime;

      // Check memory usage
      const memUsage = process.memoryUsage();
      const heapPercent = (memUsage.heapUsed / memUsage.heapTotal) * 100;

      // Check uptime
      const uptime = process.uptime();

      // Check stats consistency
      const requestsPerSecond =
        (stats.totalRequests / uptime) * (CONFIG.HEALTH_CHECK_INTERVAL / 1000);

      // Mark health status
      const wasHealthy = isHealthy;
      isHealthy =
        !stats.memoryLeak.detected &&
        heapPercent < CONFIG.MEMORY_THRESHOLD_CRITICAL * 100 &&
        uptime > 0;

      if (isHealthy) {
        consecutiveFailures = 0;
      } else {
        consecutiveFailures++;
      }

      // Log status if changed
      if (wasHealthy !== isHealthy) {
        const statusMsg = isHealthy ? 'healthy' : 'unhealthy';
        logger.warn(`Health status changed to: ${statusMsg}`, {
          heapPercent: Math.round(heapPercent),
          memoryLeakDetected: stats.memoryLeak.detected,
          consecutiveFailures
        });
      }

      // Force restart if too many failures
      if (consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
        logger.error('Health check failed repeatedly, initiating graceful shutdown', {
          consecutiveFailures
        });
        // Graceful shutdown would be triggered here
      }

      lastHealthCheckTime = now;
    } catch (err) {
      logger.error('Health check error:', {
        message: err?.message,
        stack: err?.stack?.substring(0, 300)
      });
      consecutiveFailures++;
    }
  };

  // Run health checks periodically
  const healthCheckInterval = setInterval(performHealthCheck, CONFIG.HEALTH_CHECK_INTERVAL);

  // Cleanup on shutdown
  server.on('close', () => {
    clearInterval(healthCheckInterval);
  });

  // Initial health check
  performHealthCheck();

  logger.info('Health checks enabled', {
    interval: CONFIG.HEALTH_CHECK_INTERVAL,
    timeout: CONFIG.HEALTH_CHECK_TIMEOUT
  });
}

// ==================== MEMORY MONITORING ====================
function setupMemoryMonitoring() {
  let lastMemory = process.memoryUsage().heapUsed;
  let warningTriggered = false;

  const checkMemory = () => {
    try {
      const memUsage = process.memoryUsage();
      const heapUsed = memUsage.heapUsed;
      const heapTotal = memUsage.heapTotal;
      const heapPercent = (heapUsed / heapTotal) * 100;
      const rss = memUsage.rss;
      const external = memUsage.external;

      // Update stats
      stats.system.memory = heapPercent;

      // Check critical threshold
      if (heapPercent > CONFIG.MEMORY_THRESHOLD_CRITICAL * 100) {
        logger.error('🚨 CRITICAL MEMORY USAGE', {
          heapPercent: Math.round(heapPercent),
          heapUsed: Math.round(heapUsed / 1024 / 1024),
          heapTotal: Math.round(heapTotal / 1024 / 1024),
          rss: Math.round(rss / 1024 / 1024),
          external: Math.round(external / 1024 / 1024)
        });

        // Trigger garbage collection if available
        if (global.gc) {
          logger.info('🗑️  Triggering garbage collection');
          global.gc();
        }
      } else if (heapPercent > CONFIG.MEMORY_THRESHOLD_WARNING * 100) {
        if (!warningTriggered) {
          logger.warn('⚠️  HIGH MEMORY USAGE', {
            heapPercent: Math.round(heapPercent),
            heapUsed: Math.round(heapUsed / 1024 / 1024),
            heapTotal: Math.round(heapTotal / 1024 / 1024)
          });
          warningTriggered = true;
        }
      } else {
        warningTriggered = false;
      }

      // Track memory growth
      const memoryGrowth = heapUsed - lastMemory;
      if (memoryGrowth > 50 * 1024 * 1024) {
        // 50MB growth
        logger.debug('Memory growth detected', {
          growth: Math.round(memoryGrowth / 1024 / 1024),
          heapUsed: Math.round(heapUsed / 1024 / 1024),
          requests: stats.totalRequests
        });
      }
      lastMemory = heapUsed;
    } catch (err) {
      logger.error('Memory check error:', {
        message: err?.message
      });
    }
  };

  // Run memory checks periodically
  const memoryCheckInterval = setInterval(checkMemory, MEMORY_CHECK_INTERVAL);

  // Initial check
  checkMemory();

  logger.info('Memory monitoring enabled', {
    warningThreshold: `${CONFIG.MEMORY_THRESHOLD_WARNING * 100}%`,
    criticalThreshold: `${CONFIG.MEMORY_THRESHOLD_CRITICAL * 100}%`,
    interval: MEMORY_CHECK_INTERVAL
  });
}

// ==================== GRACEFUL SHUTDOWN ====================
function setupGracefulShutdown(server, io) {
  let isShuttingDown = false;

  const handleShutdown = (signal) => {
    if (isShuttingDown) {
      logger.warn(`Already shutting down, ignoring ${signal}`);
      return;
    }

    isShuttingDown = true;
    logger.info(`Received ${signal}, initiating graceful shutdown...`);

    // Set shutdown timeout (force exit if takes too long)
    const shutdownTimeout = setTimeout(() => {
      logger.error('Shutdown timeout exceeded, forcing exit');
      process.exit(1);
    }, 30000); // 30 seconds

    // Perform graceful shutdown
    gracefulShutdown(server, io).then(() => {
      clearTimeout(shutdownTimeout);
      logger.info('Graceful shutdown complete');
      process.exit(0);
    }).catch((err) => {
      clearTimeout(shutdownTimeout);
      logger.error('Shutdown error:', {
        message: err?.message,
        stack: err?.stack?.substring(0, 300)
      });
      process.exit(1);
    });
  };

  // Handle shutdown signals
  process.on('SIGTERM', () => handleShutdown('SIGTERM'));
  process.on('SIGINT', () => handleShutdown('SIGINT'));

  // Handle uncaught exceptions
  process.on('uncaughtException', (err) => {
    logger.error('🚨 Uncaught Exception', {
      message: err?.message,
      stack: err?.stack?.substring(0, 500),
      code: err?.code,
      errno: err?.errno
    });

    // Don't handle further - let system take over
    if (!isShuttingDown) {
      handleShutdown('uncaughtException');
    }
  });

  // Handle unhandled rejections
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('🚨 Unhandled Rejection', {
      reason:
        reason instanceof Error
          ? reason.message
          : String(reason).substring(0, 200),
      stack:
        reason instanceof Error ? reason.stack?.substring(0, 500) : undefined,
      promise: String(promise).substring(0, 100)
    });

    // Don't handle further - let system take over
    if (!isShuttingDown) {
      handleShutdown('unhandledRejection');
    }
  });

  // Handle exit
  process.on('exit', (code) => {
    logger.info('Process exiting', {
      code,
      uptime: process.uptime(),
      totalRequests: stats.totalRequests,
      memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024)
    });
  });

  logger.info('Graceful shutdown handlers registered');
}

// ==================== START APPLICATION ====================
logger.info(`🚀 Starting Redirector Pro v${VERSION}...`);

start().catch((err) => {
  console.error(`\n❌ Fatal error: ${err?.message || 'Unknown error'}\n`);
  logger.error('Startup failed', {
    message: err?.message,
    stack: err?.stack?.substring(0, 500)
  });
  process.exit(1);
});

// ==================== PROCESS WARNINGS ====================

// Warn about deprecated Node.js versions
const nodeVersion = process.version;
const majorVersion = parseInt(nodeVersion.split('.')[0].substring(1), 10);

if (majorVersion < 16) {
  logger.warn(`⚠️  Running on Node.js ${nodeVersion}, which is no longer supported. Please upgrade to Node.js 16+.`);
} else if (majorVersion < 18) {
  logger.warn(`⚠️  Running on Node.js ${nodeVersion}, which is in maintenance mode. Consider upgrading to Node.js 18+.`);
}

// Warn about missing GC flag
if (!global.gc) {
  logger.warn('⚠️  Garbage collection is not exposed. Run with --expose-gc for better memory management.');
}

// Warn about production configuration
if (CONFIG.NODE_ENV === 'production') {
  if (!CONFIG.DATABASE_URL) {
    logger.warn('⚠️  Running in production without a database. Links will be lost on restart.');
  }
  if (!CONFIG.REDIS_URL) {
    logger.warn('⚠️  Running in production without Redis. Distributed sessions and queues disabled.');
  }
  if (!CONFIG.ENABLE_ENCRYPTION) {
    logger.warn('⚠️  Running in production without encryption. Enable ENABLE_ENCRYPTION for security.');
  }
  if (!CONFIG.HTTPS_ENABLED) {
    logger.warn('⚠️  Running in production without HTTPS. Set HTTPS_ENABLED=true or use reverse proxy.');
  }
}

// Export for testing
module.exports = { start, VERSION };