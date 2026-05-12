// render-start.js - Complete Render startup with quote fixing
const { spawn, execSync } = require('child_process');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');

console.log('\n' + '='.repeat(60));
console.log('🚀 REDIRECTOR PRO - RENDER STARTUP SEQUENCE');
console.log('='.repeat(60));

// Fix smart quotes in JavaScript files
async function fixQuotesInFile(filePath) {
  try {
    let content = await fs.readFile(filePath, 'utf8');
    let modified = false;
    
    if (content.includes('‘') || content.includes('’')) {
      content = content.replace(/[‘’]/g, "'");
      modified = true;
    }
    
    if (content.includes('“') || content.includes('”')) {
      content = content.replace(/[“”]/g, '"');
      modified = true;
    }
    
    if (modified) {
      await fs.writeFile(filePath, content, 'utf8');
      console.log(`   ✅ Fixed quotes: ${path.basename(filePath)}`);
      return true;
    }
    return false;
  } catch (err) {
    console.error(`   ❌ Error fixing ${filePath}:`, err.message);
    return false;
  }
}

async function fixAllQuotes() {
  console.log('\n🔧 FIXING SMART QUOTES IN JAVASCRIPT FILES...');
  
  const walkDir = async (dir) => {
    let fixedCount = 0;
    let files = [];
    try {
      files = await fs.readdir(dir);
    } catch (err) {
      return 0;
    }
    
    for (const file of files) {
      const filePath = path.join(dir, file);
      try {
        const stat = await fs.stat(filePath);
        
        if (stat.isDirectory()) {
          if (file !== 'node_modules' && file !== '.git' && file !== 'logs' && file !== 'data' && file !== 'backups') {
            fixedCount += await walkDir(filePath);
          }
        } else if (file.endsWith('.js')) {
          if (await fixQuotesInFile(filePath)) fixedCount++;
        }
      } catch (err) {
        // Ignore permission errors
      }
    }
    
    return fixedCount;
  };
  
  const fixedFiles = await walkDir(process.cwd());
  console.log(`\n📊 Fixed ${fixedFiles} JavaScript file(s)`);
  return fixedFiles;
}

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
    const requiredFiles = ['server.js', 'core.js', 'routes.js'];
    const optionalFiles = ['.env', 'public/index.html', 'public/login.html'];
    const missing = [];
    const missingOptional = [];
    
    console.log('\n📁 REQUIRED FILES:');
    for (const file of requiredFiles) {
        try {
            await fs.access(file);
            console.log(`   ✅ ${file} exists`);
        } catch {
            missing.push(file);
            console.log(`   ❌ ${file} MISSING`);
        }
    }
    
    console.log('\n📁 OPTIONAL FILES:');
    for (const file of optionalFiles) {
        try {
            await fs.access(file);
            console.log(`   ✅ ${file} exists`);
        } catch {
            missingOptional.push(file);
            console.log(`   ⚠️  ${file} not found (optional)`);
        }
    }
    
    if (missing.length > 0) {
        console.error(`\n❌ Missing required files: ${missing.join(', ')}`);
        return false;
    }
    
    // Create default .env if missing (but warn about security)
    if (missingOptional.includes('.env')) {
        console.log('\n⚠️  WARNING: Creating default .env file with insecure defaults!');
        console.log('   Please replace with your actual values ASAP.');
        const crypto = require('crypto');
        const defaultEnv = `NODE_ENV=production
PORT=${process.env.PORT || 10000}
HOST=0.0.0.0
TARGET_URL=https://example.com
SESSION_SECRET=${crypto.randomBytes(32).toString('hex')}
METRICS_API_KEY=${crypto.randomBytes(32).toString('hex')}
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.VT0ZO2uOEv6VIO
REQUEST_SIGNING_SECRET=${crypto.randomBytes(32).toString('hex')}`;
        await fs.writeFile('.env', defaultEnv);
        console.log('   ✅ Created default .env file');
    }
    
    return true;
}

// Check directories
async function checkDirectories() {
    const dirs = ['logs', 'public', 'data', 'backups'];
    console.log('\n📁 DIRECTORY CHECK:');
    for (const dir of dirs) {
        try {
            await fs.mkdir(dir, { recursive: true });
            console.log(`   ✅ ${dir}/ directory ready`);
        } catch (err) {
            console.log(`   ⚠️  Could not create ${dir}/: ${err.message}`);
        }
    }
}

// Validate critical files have no smart quotes
async function validateCriticalFiles() {
    console.log('\n🔍 VALIDATING CRITICAL FILES FOR SMART QUOTES...');
    const criticalFiles = ['core.js', 'server.js', 'routes.js'];
    let hasIssues = false;
    
    for (const file of criticalFiles) {
        try {
            const content = await fs.readFile(file, 'utf8');
            const smartQuotes = content.match(/[‘’“”]/g);
            if (smartQuotes) {
                console.error(`   ❌ ${file} still has ${smartQuotes.length} smart quote(s)!`);
                hasIssues = true;
                // Fix it again
                await fixQuotesInFile(file);
            } else {
                console.log(`   ✅ ${file} is clean`);
            }
        } catch (err) {
            console.error(`   ❌ Cannot read ${file}:`, err.message);
            hasIssues = true;
        }
    }
    
    return !hasIssues;
}

// Main startup
(async () => {
    try {
        // Step 1: Fix all smart quotes in JS files
        await fixAllQuotes();
        
        // Step 2: Validate critical files
        const valid = await validateCriticalFiles();
        if (!valid) {
            console.error('\n❌ Critical files still have quote issues after fixing');
            // Try one more time with sync method as fallback
            console.log('\n🔄 Attempting fallback fix with sed...');
            try {
                // Fixed sed commands - using double quotes and escaping properly
                execSync('find . -name "*.js" -type f -exec sed -i "s/[‘’]/'\''/g" {} \\;', { 
                    stdio: 'inherit',
                    shell: '/bin/bash'
                });
                execSync('find . -name "*.js" -type f -exec sed -i "s/[“”]/\\"/g" {} \\;', { 
                    stdio: 'inherit',
                    shell: '/bin/bash'
                });
                console.log('   ✅ Fallback fix completed');
            } catch (err) {
                console.error('   ⚠️ Fallback fix failed, continuing anyway');
            }
        }
        
        // Step 3: Check files and directories
        console.log('\n🔍 FILE SYSTEM CHECK:');
        const filesOk = await checkFiles();
        if (!filesOk) {
            console.error('\n❌ File system check failed');
            process.exit(1);
        }
        
        await checkDirectories();
        
        // Step 4: Start the server
        console.log('\n🚀 Starting server...');
        console.log(`   Command: node --max-old-space-size=512 --expose-gc server.js`);
        console.log(`   Port: ${process.env.PORT}`);
        console.log(`   Time: ${new Date().toISOString()}`);
        console.log('\n' + '-'.repeat(60) + '\n');
        
        // Spawn the server process with GC enabled
        const server = spawn('node', ['--max-old-space-size=512', '--expose-gc', 'server.js'], {
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
        
    } catch (err) {
        console.error('\n❌ Startup error:', err.message);
        console.error(err.stack);
        process.exit(1);
    }
})();
