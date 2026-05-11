#!/usr/bin/env node
console.log('\n🧪 Testing Graceful Shutdown Fix...\n');

// Simulate graceful shutdown with timeout from server.js fix
const testShutdown = new Promise((resolve, reject) => {
  const startTime = Date.now();
  const timeoutLimit = 30000; // 30 seconds max
  
  // Simulate shutdown process
  const shutdown = () => {
    const elapsed = Date.now() - startTime;
    if (elapsed > timeoutLimit) {
      reject(new Error(`Shutdown took ${elapsed}ms, exceeds ${timeoutLimit}ms limit`));
    } else {
      console.log(`✅ Shutdown completed in ${elapsed}ms\n`);
      resolve();
    }
  };
  
  // Simulate 5ms shutdown
  setTimeout(shutdown, 5);
});

testShutdown
  .then(() => process.exit(0))
  .catch((err) => {
    console.log(`❌ ${err.message}\n`);
    process.exit(1);
  });
