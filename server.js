// server.js – Entry point
require('dotenv').config();
const express = require('express');
const http = require('http');
const { initCore, gracefulShutdown, CONFIG } = require('./core');
const { createServer } = require('./routes');

async function start() {
  await initCore();    // ensures DB, Redis, queues, key manager are ready
  
  const app = express();
  const server = http.createServer(app);
  const { io } = createServer(app, server);
  
  const port = CONFIG.PORT;
  const host = CONFIG.HOST;
  
  server.listen(port, host, () => {
    console.log(`✅ Redirector Pro v4.2.0 running on http://${host}:${port}`);
    console.log(`📚 API docs: http://${host}:${port}/api-docs`);
    console.log(`👑 Admin: http://${host}:${port}/admin`);
  });
  
  process.on('SIGTERM', () => gracefulShutdown(server, io));
  process.on('SIGINT', () => gracefulShutdown(server, io));
}

start().catch(err => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
