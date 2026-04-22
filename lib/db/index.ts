/**
 * Windrose Database Connection
 * 
 * PostgreSQL connection using Drizzle ORM and pg driver.
 * 
 * Environment variables:
 * - DATABASE_URL: PostgreSQL connection string
 */

import { drizzle } from 'drizzle-orm/node-postgres';
import pg from 'pg';

const { Pool } = pg;

// Create connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Create Drizzle instance without schema (schema is imported dynamically)
export const db = drizzle(pool);

// Default export for convenience
export default db;

// Export pool for direct queries if needed
export { pool };

// Dynamically import schema at runtime
export async function getSchema() {
  const schema = await import('./schema/index');
  return schema;
}
