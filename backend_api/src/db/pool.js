const { Pool } = require('pg');
const { getConfig } = require('../config/env');

let pool;

/**
 * Build pg Pool configuration from env.
 * Prefer DATABASE_URL (commonly used in production), fallback to PG* vars.
 */
function buildPoolConfig() {
  const config = getConfig();
  if (config.db.databaseUrl) {
    return {
      connectionString: config.db.databaseUrl,
    };
  }

  const { host, port, database, user, password } = config.db.pg;

  return {
    host: host || undefined,
    port: port || undefined,
    database: database || undefined,
    user: user || undefined,
    password: password || undefined,
  };
}

// PUBLIC_INTERFACE
function getDbPool() {
  /** Returns a singleton pg Pool instance for the application. */
  if (!pool) {
    pool = new Pool(buildPoolConfig());
  }
  return pool;
}

// PUBLIC_INTERFACE
async function dbQuery(text, params) {
  /** Executes a SQL query using the shared pg Pool. */
  const p = getDbPool();
  return p.query(text, params);
}

module.exports = {
  getDbPool,
  dbQuery,
};
