// render-start.js
const { spawn } = require('child_process');
const fs = require('fs').promises;
const path = require('path');

console.log('\n' + '='.repeat(60));
console.log('🚀 REDIRECTOR PRO - RENDER STARTUP SEQUENCE');
console.log('='.repeat(60));

// Log environment for debugging
console.log('\n📋 ENVIRONMENT CHECK:');
console.log(`   PORT: ${process.env.PORT || '❌ NOT SET'}`);
console.log(`   NODE_ENV: ${process.env.NODE_ENV || 'not set'}`);
console.log(`   Current directory: ${process.cwd()}`);

// Check if PORT is set
if (!process.env.PORT) {
    console.error('\n❌ CRITICAL: PORT environment variable is not set!');
    console.error('   Render should automatically set this.');
    console.error('   Please check your service configuration.');
    process.exit(1);
}

// Log available environment variables (without values)
console.log('\n📊 Available env vars:', Object.keys(process.env).sort().join(', '));

// Check if required files exist
async function checkFiles() {
    const requiredFiles = ['server.js', '.env', 'public/index.html', 'public/login.html'];
    const missing = [];
    
    for (const file of requiredFiles) {
        try {
            await fs.access(file);
            console.log(`   ✅ ${file} exists`);
        } catch {
            if (file === '.env') {
                console.log(`   ⚠️  ${file} not found (optional)`);
            } else {
                missing.push(file);
                console.log(`   ❌ ${file} MISSING`);
            }
        }
    }
    
    if (missing.length > 0) {
        console.error(`\n❌ Missing required files: ${missing.join(', ')}`);
        return false;
    }
    return true;
}

// Check directories
async function checkDirectories() {
    const dirs = ['logs', 'public', 'data', 'backups'];
    for (const dir of dirs) {
        try {
            await fs.mkdir(dir, { recursive: true });
            console.log(`   ✅ ${dir}/ directory ready`);
        } catch (err) {
            console.log(`   ⚠️  Could not create ${dir}/: ${err.message}`);
        }
    }
}

// Main startup
(async () => {
    console.log('\n🔍 FILE SYSTEM CHECK:');
    const filesOk = await checkFiles();
    if (!filesOk) {
        console.error('\n❌ File system check failed');
        process.exit(1);
    }
    
    await checkDirectories();
    
    console.log('\n🚀 Starting server...');
    console.log(`   Command: node --max-old-space-size=512 server.js`);
    console.log(`   Port: ${process.env.PORT}`);
    console.log(`   Time: ${new Date().toISOString()}`);
    console.log('\n' + '-'.repeat(60) + '\n');
    
    // Spawn the server process
    const server = spawn('node', ['--max-old-space-size=512', 'server.js'], {
        stdio: 'inherit',
        env: process.env
    });
    
    server.on('error', (err) => {
        console.error('\n❌ Failed to start server:', err);
        process.exit(1);
    });
    
    server.on('exit', (code, signal) => {
        if (code !== 0) {
            console.error(`\n❌ Server exited with code ${code} (signal: ${signal})`);
            process.exit(code || 1);
        }
    });
    
    // Handle graceful shutdown
    process.on('SIGTERM', () => {
        console.log('\n📡 Received SIGTERM, forwarding to server...');
        server.kill('SIGTERM');
    });
    
    process.on('SIGINT', () => {
        console.log('\n📡 Received SIGINT, forwarding to server...');
        server.kill('SIGINT');
    });
})();
