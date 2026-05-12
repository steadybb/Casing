const fs = require('fs');
const path = require('path');

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
      console.log(`✅ Fixed: ${filePath}`);
      return true;
    }
    return false;
  } catch (err) {
    console.error(`❌ Error fixing ${filePath}:`, err.message);
    return false;
  }
}

function walkDir(dir) {
  let fixedCount = 0;
  const files = fs.readdirSync(dir);
  
  for (const file of files) {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    
    if (stat.isDirectory()) {
      if (file !== 'node_modules' && file !== '.git') {
        fixedCount += walkDir(filePath);
      }
    } else if (file.endsWith('.js')) {
      if (fixQuotesInFile(filePath)) fixedCount++;
    }
  }
  
  return fixedCount;
}

// Fix all JS files
console.log('🔧 Fixing quote characters in JavaScript files...');
const fixed = walkDir(process.cwd());
console.log(`\n✅ Fixed ${fixed} file(s). Restart your application.`);
