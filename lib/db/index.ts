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
import * as schema from './schema/index';

const { Pool } = pg;

// Create connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Create Drizzle instance with schema
export const db = drizzle(pool, { schema });

// Export pool for direct queries if needed
export { pool };

// Export schema types for convenience
export * from './schema/index';