// test-start.js - Direct test to see the error
require('dotenv').config();

console.log('Testing core.js load...');
try {
    const core = require('./core');
    console.log('✅ core.js loaded successfully');
    console.log('CONFIG loaded:', Object.keys(core.CONFIG).slice(0, 10));
} catch (err) {
    console.error('❌ Error loading core.js:');
    console.error(err.message);
    console.error(err.stack);
    process.exit(1);
}

console.log('\nTesting server.js...');
try {
    require('./server');
    console.log('✅ server.js loaded successfully');
} catch (err) {
    console.error('❌ Error loading server.js:');
    console.error(err.message);
    console.error(err.stack);
}
