// render-start.js - Complete Render startup with error capture
const { spawn } = require('child_process');
const fs = require('fs').promises;
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
  
  const criticalFiles = ['core.js', 'server.js', 'routes.js'];
  let fixedCount = 0;
  
  for (const file of criticalFiles) {
    if (await fixQuotesInFile(file)) fixedCount++;
  }
  
  console.log(`\n📊 Fixed ${fixedCount} JavaScript file(s)`);
  return fixedCount;
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

// Check if required files exist
async function checkFiles() {
    const requiredFiles = ['server.js', 'core.js', 'routes.js'];
    const missing = [];
    
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
    
    if (missing.length > 0) {
        console.error(`\n❌ Missing required files: ${missing.join(', ')}`);
        return false;
    }
    
    // Check for .env file
    try {
        await fs.access('.env');
        console.log('   ✅ .env exists');
    } catch {
        console.log('   ⚠️  .env not found');
    }
    
    return true;
}

// Check and create directories
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

// Validate critical files are clean
async function validateCriticalFiles() {
    console.log('\n🔍 VALIDATING CRITICAL FILES...');
    const criticalFiles = ['core.js', 'server.js', 'routes.js'];
    let allClean = true;
    
    for (const file of criticalFiles) {
        try {
            const content = await fs.readFile(file, 'utf8');
            const smartQuotes = content.match(/[‘’“”]/g);
            if (smartQuotes) {
                console.error(`   ❌ ${file} still has ${smartQuotes.length} smart quote(s)!`);
                allClean = false;
            } else {
                console.log(`   ✅ ${file} is clean`);
            }
        } catch (err) {
            console.error(`   ❌ Cannot read ${file}:`, err.message);
            allClean = false;
        }
    }
    
    return allClean;
}

// Main startup
(async () => {
    try {
        // Step 1: Fix all smart quotes in JS files
        await fixAllQuotes();
        
        // Step 2: Validate critical files
        await validateCriticalFiles();
        
        // Step 3: Check files and directories
        console.log('\n🔍 FILE SYSTEM CHECK:');
        const filesOk = await checkFiles();
        if (!filesOk) {
            console.error('\n❌ File system check failed');
            process.exit(1);
        }
        
        await checkDirectories();
        
        // Step 4: Start the server with error capture
        console.log('\n🚀 Starting server...');
        console.log(`   Command: node --max-old-space-size=512 --expose-gc server.js`);
        console.log(`   Port: ${process.env.PORT}`);
        console.log(`   Time: ${new Date().toISOString()}`);
        console.log('\n' + '-'.repeat(60) + '\n');
        
        // Spawn the server process with GC enabled and capture errors
        const server = spawn('node', ['--max-old-space-size=512', '--expose-gc', 'server.js'], {
            stdio: ['pipe', 'pipe', 'pipe'],
            env: process.env
        });
        
        // Capture stdout
        server.stdout.on('data', (data) => {
            console.log(data.toString());
        });
        
        // Capture stderr - THIS IS CRITICAL
        server.stderr.on('data', (data) => {
            const errorMsg = data.toString();
            console.error(errorMsg);
            
            // If we see certain errors, log them clearly
            if (errorMsg.includes('Error') || errorMsg.includes('Cannot find')) {
                console.error('\n❌ SERVER ERROR DETECTED:');
                console.error(errorMsg);
            }
        });
        
        server.on('error', (err) => {
            console.error('\n❌ Failed to start server:', err);
            process.exit(1);
        });
        
        server.on('exit', (code, signal) => {
            if (code !== 0) {
                console.error(`\n❌ Server exited with code ${code} (signal: ${signal})`);
                console.error('\n📝 TROUBLESHOOTING:');
                console.error('   1. Check if all required env vars are set');
                console.error('   2. Verify database connection if using DATABASE_URL');
                console.error('   3. Check Redis connection if using REDIS_URL');
                console.error('   4. Look for errors above this message');
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
