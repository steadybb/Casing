#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

console.log('\n🔧 FIXING SMART QUOTES IN JAVASCRIPT FILES');
console.log('='.repeat(50));

function fixQuotesInFile(filePath) {
  try {
    let content = fs.readFileSync(filePath, 'utf8');
    let modified = false;
    
    // Fix single quotes
    if (content.includes('‘') || content.includes('’')) {
      content = content.replace(/[‘’]/g, "'");
      modified = true;
    }
    
    // Fix double quotes
    if (content.includes('“') || content.includes('”')) {
      content = content.replace(/[“”]/g, '"');
      modified = true;
    }
    
    if (modified) {
      fs.writeFileSync(filePath, content, 'utf8');
      console.log(`  ✅ Fixed: ${path.basename(filePath)}`);
      return true;
    }
    return false;
  } catch (err) {
    console.error(`  ❌ Error: ${path.basename(filePath)} - ${err.message}`);
    return false;
  }
}

function walkDir(dir) {
  let fixedCount = 0;
  let files = [];
  
  try {
    files = fs.readdirSync(dir);
  } catch (err) {
    return 0;
  }
  
  for (const file of files) {
    const filePath = path.join(dir, file);
    try {
      const stat = fs.statSync(filePath);
      
      if (stat.isDirectory()) {
        // Skip node_modules and other directories
        if (!['node_modules', '.git', 'logs', 'data', 'backups', 'coverage', 'dist', 'build'].includes(file)) {
          fixedCount += walkDir(filePath);
        }
      } else if (file.endsWith('.js')) {
        if (fixQuotesInFile(filePath)) fixedCount++;
      }
    } catch (err) {
      // Ignore permission errors
    }
  }
  
  return fixedCount;
}

// Fix all JS files
const fixedFiles = walkDir(process.cwd());
console.log(`\n📊 Fixed ${fixedFiles} file(s)`);
console.log('='.repeat(50) + '\n');

if (fixedFiles > 0) {
  console.log('✅ Quote fixing completed successfully!\n');
} else {
  console.log('ℹ️ No files needed fixing.\n');
}
