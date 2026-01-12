const { verifyAccessToken } = require('../auth/jwt');

/**
 * Extracts Bearer token from Authorization header.
 */
function getBearerToken(req) {
  const header = req.headers.authorization || '';
  if (!header) return '';
  const [scheme, token] = header.split(' ');
  if (!scheme || scheme.toLowerCase() !== 'bearer') return '';
  return token || '';
}

// PUBLIC_INTERFACE
function requireAuth(req, res, next) {
  /** Requires a valid JWT access token in Authorization: Bearer <token>. */
  try {
    const token = getBearerToken(req);
    if (!token) {
      return res.status(401).json({ message: 'Missing Authorization bearer token.' });
    }
    const payload = verifyAccessToken(token);

    req.auth = {
      userId: payload.sub,
      email: payload.email,
      roles: Array.isArray(payload.roles) ? payload.roles : [],
    };

    return next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired access token.' });
  }
}

// PUBLIC_INTERFACE
function requireRole(requiredRole) {
  /** Requires that the authenticated user has the specified role. */
  return (req, res, next) => {
    const roles = req.auth?.roles || [];
    if (!roles.includes(requiredRole)) {
      return res.status(403).json({ message: 'Forbidden: insufficient role.' });
    }
    return next();
  };
}

module.exports = {
  requireAuth,
  requireRole,
};
