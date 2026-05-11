#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

console.log('\n🔍 Verifying Installation...\n');

const checks = [
  { name: 'Node version >=18', check: () => parseInt(process.version.split('.')[0].slice(1)) >= 18 },
  { name: '.env file exists', check: () => fs.existsSync('.env') },
  { name: 'node_modules exists', check: () => fs.existsSync('node_modules') },
  { name: 'server.js exists', check: () => fs.existsSync('server.js') },
  { name: 'package-lock.json exists', check: () => fs.existsSync('package-lock.json') }
];

let passed = 0;
checks.forEach(({ name, check }) => {
  const result = check();
  console.log(`${result ? '✅' : '❌'} ${name}`);
  if (result) passed++;
});

console.log(`\n${passed}/${checks.length} checks passed\n`);
process.exit(passed === checks.length ? 0 : 1);
