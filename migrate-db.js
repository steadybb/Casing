// migrate-db.js

const { Client } = require('pg');

async function migrate() {
    const client = new Client();
    await client.connect();

    try {
        // Add missing columns
        await client.query(`ALTER TABLE your_table_name ADD COLUMN IF NOT EXISTS new_column_name VARCHAR(255);`);

        // Create indexes
        await client.query(`CREATE INDEX IF NOT EXISTS index_name ON your_table_name(column_name);`);

        console.log('Migration completed successfully.');
    } catch (err) {
        console.error('Migration failed:', err);
    } finally {
        await client.end();
    }
}

migrate();