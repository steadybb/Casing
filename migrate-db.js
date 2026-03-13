const { Pool } = require('pg');
const dotenv = require('dotenv');

dotenv.config();

async function migrateDatabase() {
  if (!process.env.DATABASE_URL) {
    console.log('No DATABASE_URL found, skipping migration');
    process.exit(0);
  }

  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });

  try {
    console.log('🔧 Running database migrations...');
    
    // Add metadata column to links table
    await pool.query(`
      ALTER TABLE links 
      ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';
    `);
    console.log('✅ Added metadata column to links table');
    
    // Add last_accessed column if missing
    await pool.query(`
      ALTER TABLE links 
      ADD COLUMN IF NOT EXISTS last_accessed TIMESTAMP;
    `);
    console.log('✅ Verified last_accessed column');
    
    // Add status column if missing
    await pool.query(`
      ALTER TABLE links 
      ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';
    `);
    console.log('✅ Verified status column');
    
    console.log('✅ Database migration completed successfully');
  } catch (err) {
    console.error('❌ Migration error:', err);
  } finally {
    await pool.end();
    process.exit(0);
  }
}

migrateDatabase();