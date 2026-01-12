const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { validationResult } = require('express-validator');

const { dbQuery } = require('../db/pool');
const { signAccessToken } = require('../auth/jwt');
const { getConfig } = require('../config/env');

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function buildCookieOptions() {
  const config = getConfig();
  return {
    httpOnly: true,
    secure: config.auth.refresh.cookieSecure,
    sameSite: config.auth.refresh.cookieSameSite,
    path: '/auth',
  };
}

async function fetchUserWithRolesById(userId) {
  const result = await dbQuery(
    `
    SELECT 
      u.id,
      u.email,
      u.display_name,
      u.is_active,
      u.created_at,
      u.updated_at,
      u.last_login_at,
      COALESCE(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL), '{}') AS roles
    FROM users u
    LEFT JOIN user_roles ur ON ur.user_id = u.id
    LEFT JOIN roles r ON r.id = ur.role_id
    WHERE u.id = $1
    GROUP BY u.id
    `,
    [userId]
  );

  return result.rows[0] || null;
}

async function fetchUserWithRolesByEmail(email) {
  const result = await dbQuery(
    `
    SELECT 
      u.id,
      u.email,
      u.password_hash,
      u.display_name,
      u.is_active,
      u.created_at,
      u.updated_at,
      u.last_login_at,
      COALESCE(array_agg(r.name) FILTER (WHERE r.name IS NOT NULL), '{}') AS roles
    FROM users u
    LEFT JOIN user_roles ur ON ur.user_id = u.id
    LEFT JOIN roles r ON r.id = ur.role_id
    WHERE lower(u.email) = lower($1)
    GROUP BY u.id
    `,
    [email]
  );

  return result.rows[0] || null;
}

async function ensureUserHasRole(userId, roleName) {
  const roleRes = await dbQuery('SELECT id FROM roles WHERE name = $1', [roleName]);
  const role = roleRes.rows[0];
  if (!role) throw new Error(`Role not found: ${roleName}`);

  await dbQuery(
    `
    INSERT INTO user_roles (user_id, role_id)
    VALUES ($1, $2)
    ON CONFLICT (user_id, role_id) DO NOTHING
    `,
    [userId, role.id]
  );
}

function toFrontendUser(userRow) {
  // Frontend expects user.role (single). We provide the "primary" role as first role, plus roles[].
  const roles = Array.isArray(userRow.roles) ? userRow.roles : [];
  return {
    id: userRow.id,
    email: userRow.email,
    name: userRow.display_name,
    role: roles[0] || 'user',
    roles,
    isActive: userRow.is_active,
    lastLoginAt: userRow.last_login_at,
  };
}

class AuthController {
  async register(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Invalid input.', errors: errors.array() });
    }

    const { email, password, name } = req.body;
    const config = getConfig();

    const existing = await dbQuery('SELECT 1 FROM users WHERE lower(email) = lower($1)', [email]);
    if (existing.rowCount > 0) {
      return res.status(409).json({ message: 'Email already registered.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const created = await dbQuery(
      `
      INSERT INTO users (email, password_hash, display_name, is_active)
      VALUES ($1, $2, $3, true)
      RETURNING id
      `,
      [email, passwordHash, name]
    );

    const userId = created.rows[0].id;

    // Default role: user
    await ensureUserHasRole(userId, 'user');

    const user = await fetchUserWithRolesById(userId);
    const accessToken = signAccessToken({ userId, email: user.email, roles: user.roles });

    // Optional refresh token
    if (config.auth.refresh.enabled) {
      const refreshTokenPlain = crypto.randomBytes(48).toString('base64url');
      const refreshTokenHash = sha256Hex(refreshTokenPlain);
      const expiresAt = new Date(Date.now() + config.auth.refresh.expiresDays * 24 * 60 * 60 * 1000);

      await dbQuery(
        `
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
        VALUES ($1, $2, $3)
        `,
        [userId, refreshTokenHash, expiresAt.toISOString()]
      );

      res.cookie(config.auth.refresh.cookieName, refreshTokenPlain, {
        ...buildCookieOptions(),
        expires: expiresAt,
      });
    }

    return res.status(201).json({
      accessToken,
      user: toFrontendUser(user),
    });
  }

  async login(req, res) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Invalid input.', errors: errors.array() });
    }

    const { email, password } = req.body;
    const config = getConfig();

    const userRow = await fetchUserWithRolesByEmail(email);
    if (!userRow || !userRow.is_active) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    const isValid = await bcrypt.compare(password, userRow.password_hash);
    if (!isValid) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }

    await dbQuery('UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1', [userRow.id]);

    const accessToken = signAccessToken({ userId: userRow.id, email: userRow.email, roles: userRow.roles });

    if (config.auth.refresh.enabled) {
      const refreshTokenPlain = crypto.randomBytes(48).toString('base64url');
      const refreshTokenHash = sha256Hex(refreshTokenPlain);
      const expiresAt = new Date(Date.now() + config.auth.refresh.expiresDays * 24 * 60 * 60 * 1000);

      await dbQuery(
        `
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
        VALUES ($1, $2, $3)
        `,
        [userRow.id, refreshTokenHash, expiresAt.toISOString()]
      );

      res.cookie(config.auth.refresh.cookieName, refreshTokenPlain, {
        ...buildCookieOptions(),
        expires: expiresAt,
      });
    }

    const user = await fetchUserWithRolesById(userRow.id);

    return res.status(200).json({
      accessToken,
      user: toFrontendUser(user),
    });
  }

  async logout(req, res) {
    const config = getConfig();
    const refreshTokenPlain = req.cookies?.[config.auth.refresh.cookieName];

    // Best-effort revoke refresh token if present
    if (refreshTokenPlain) {
      const refreshTokenHash = sha256Hex(refreshTokenPlain);
      await dbQuery('UPDATE refresh_tokens SET revoked_at = now(), updated_at = now() WHERE token_hash = $1', [
        refreshTokenHash,
      ]);
    }

    res.clearCookie(config.auth.refresh.cookieName, buildCookieOptions());
    return res.status(200).json({ message: 'Logged out.' });
  }

  async me(req, res) {
    // req.auth set by requireAuth middleware
    const user = await fetchUserWithRolesById(req.auth.userId);
    if (!user) return res.status(404).json({ message: 'User not found.' });
    return res.status(200).json({ user: toFrontendUser(user) });
  }
}

module.exports = new AuthController();
