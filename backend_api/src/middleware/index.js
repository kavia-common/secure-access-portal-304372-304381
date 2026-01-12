const { requireAuth, requireRole } = require('./auth');

// This file will export middleware as the application grows
module.exports = {
  requireAuth,
  requireRole,
};
