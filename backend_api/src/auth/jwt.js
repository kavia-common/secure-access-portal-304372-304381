const jwt = require('jsonwebtoken');
const { getConfig } = require('../config/env');

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

// PUBLIC_INTERFACE
function signAccessToken({ userId, email, roles }) {
  /** Signs a JWT access token embedding user identity and roles for RBAC checks. */
  const config = getConfig();
  const payload = {
    sub: userId,
    email,
    roles: Array.isArray(roles) ? roles : [],
    iat: nowSeconds(),
    type: 'access',
  };

  return jwt.sign(payload, config.auth.jwtSecret, {
    expiresIn: config.auth.jwtExpiresIn,
    issuer: config.auth.jwtIssuer,
    audience: config.auth.jwtAudience,
  });
}

// PUBLIC_INTERFACE
function verifyAccessToken(token) {
  /** Verifies a JWT access token and returns its decoded payload. Throws on invalid token. */
  const config = getConfig();
  return jwt.verify(token, config.auth.jwtSecret, {
    issuer: config.auth.jwtIssuer,
    audience: config.auth.jwtAudience,
  });
}

module.exports = {
  signAccessToken,
  verifyAccessToken,
};
