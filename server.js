// server.js – Entry point for Redirector Pro
// This file initializes the core system, creates the Express app,
// mounts routes via `createServer`, and starts the HTTP server.

require('dotenv').config();
const express = require('express');
const http = require('http');
const { initCore, gracefulShutdown, CONFIG, logger } = require('./core');
const { createServer } = require('./routes');

async function start() {
  // Initialize all shared resources (database, Redis, queues, encryption, etc.)
  await initCore();
  logger.info('Core initialization complete');

  // Create Express app and HTTP server
  const app = express();
  const server = http.createServer(app);

  // Configure server timeouts (from config)
  server.keepAliveTimeout = CONFIG.KEEP_ALIVE_TIMEOUT;
  server.headersTimeout = CONFIG.HEADERS_TIMEOUT;
  server.timeout = CONFIG.SERVER_TIMEOUT;
  server.maxHeadersCount = 1000;
  server.maxConnections = 10000;

  // Mount all routes, middleware, and Socket.IO
  const { io } = createServer(app, server);

  const PORT = CONFIG.PORT;
  const HOST = CONFIG.HOST;

  server.listen(PORT, HOST, () => {
    console.log('\n' + '='.repeat(100));
    console.log(`✅ Redirector Pro v4.2.0 running on http://${HOST}:${PORT}`);
    console.log('='.repeat(100));
    console.log(`📚 API Documentation: http://${HOST}:${PORT}/api-docs`);
    console.log(`👑 Admin Dashboard:   http://${HOST}:${PORT}/admin`);
    console.log(`📊 Health Check:      http://${HOST}:${PORT}/health`);
    console.log(`📈 Metrics:           http://${HOST}:${PORT}/metrics (requires API key)`);
    console.log(`🔗 Link Mode:         ${CONFIG.LINK_LENGTH_MODE} (switchable: ${CONFIG.ALLOW_LINK_MODE_SWITCH})`);
    console.log(`🔐 Encryption:        ${CONFIG.ENABLE_ENCRYPTION ? 'Enabled' : 'Disabled'}`);
    console.log(`💾 Database:          ${require('./core').getDbPool() ? 'Connected' : 'Disabled'}`);
    console.log(`🔄 Redis:             ${require('./core').getRedis() ? 'Connected' : 'Disabled'}`);
    console.log(`📨 Bull Queues:       ${require('./core').getQueues().redirectQueue ? 'Enabled' : 'Disabled'}`);
    console.log(`🛡️ Circuit Breakers:  ${Object.keys(require('./core').getBreakerMonitor()?.getStatus() || {}).length} active`);
    console.log('='.repeat(100) + '\n');
    logger.info('Server started successfully', { port: PORT, host: HOST, pid: process.pid });
  });

  // Graceful shutdown handlers
  process.on('SIGTERM', () => gracefulShutdown(server, io));
  process.on('SIGINT', () => gracefulShutdown(server, io));
  process.on('uncaughtException', (err) => {
    logger.error('Uncaught Exception:', err);
    gracefulShutdown(server, io);
  });
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection:', reason);
    gracefulShutdown(server, io);
  });
}

// Start the application
start().catch(err => {
  console.error('❌ Fatal error during startup:', err);
  logger.error('Fatal startup error:', err);
  process.exit(1);
});
