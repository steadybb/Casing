#!/usr/bin/env node
const { execSync } = require('child_process');
const fs = require('fs');

console.log('\n📊 Establishing Performance Baseline...\n');

const baselineDir = './tests/baselines';
if (!fs.existsSync(baselineDir)) {
  fs.mkdirSync(baselineDir, { recursive: true });
}

const baseline = {
  timestamp: new Date().toISOString(),
  compression: require('./verify-compression-fix.js'),
  memory: require('./verify-memory-fix.js'),
  shutdown: require('./verify-graceful-shutdown.js')
};

fs.writeFileSync(
  `${baselineDir}/baseline-${Date.now()}.json`,
  JSON.stringify(baseline, null, 2)
);

console.log('✅ Baseline saved\n');
process.exit(0);
