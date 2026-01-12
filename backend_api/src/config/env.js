const dotenv = require('dotenv');

dotenv.config();

function requireEnv(name) {
  const value = process.env[name];
  if (!value || !String(value).trim()) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return String(value).trim();
}

function optionalEnv(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === null || !String(value).trim()) return fallback;
  return String(value).trim();
}

function optionalBool(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === null || String(value).trim() === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
}

function optionalInt(name, fallback) {
  const value = process.env[name];
  if (value === undefined || value === null || String(value).trim() === '') return fallback;
  const parsed = Number.parseInt(String(value).trim(), 10);
  // eslint-disable-next-line no-restricted-globals
  if (isNaN(parsed)) return fallback;
  return parsed;
}

// PUBLIC_INTERFACE
function getConfig() {
  /** Returns normalized runtime configuration derived from environment variables. */
  const config = {
    server: {
      port: optionalInt('PORT', 3001),
      host: optionalEnv('HOST', '0.0.0.0'),
      nodeEnv: optionalEnv('NODE_ENV', 'development'),
    },
    cors: {
      origin: optionalEnv('CORS_ORIGIN', 'http://localhost:3000'),
    },
    db: {
      databaseUrl: optionalEnv('DATABASE_URL', ''),
      pg: {
        host: optionalEnv('PGHOST', ''),
        port: optionalInt('PGPORT', 5432),
        database: optionalEnv('PGDATABASE', ''),
        user: optionalEnv('PGUSER', ''),
        password: optionalEnv('PGPASSWORD', ''),
        sslmode: optionalEnv('PGSSLMODE', ''),
      },
    },
    auth: {
      jwtSecret: requireEnv('JWT_SECRET'),
      jwtIssuer: optionalEnv('JWT_ISSUER', 'secure-access-portal'),
      jwtAudience: optionalEnv('JWT_AUDIENCE', 'secure-access-portal-web'),
      jwtExpiresIn: optionalEnv('JWT_EXPIRES_IN', '15m'),
      refresh: {
        enabled: optionalBool('REFRESH_TOKEN_ENABLED', true),
        expiresDays: optionalInt('REFRESH_TOKEN_EXPIRES_DAYS', 30),
        cookieName: optionalEnv('REFRESH_TOKEN_COOKIE_NAME', 'refresh_token'),
        cookieSecure: optionalBool('REFRESH_TOKEN_COOKIE_SECURE', false),
        cookieSameSite: optionalEnv('REFRESH_TOKEN_COOKIE_SAMESITE', 'lax'),
      },
    },
  };

  return config;
}

module.exports = {
  getConfig,
};
