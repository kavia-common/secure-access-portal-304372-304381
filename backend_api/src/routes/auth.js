const express = require('express');
const authController = require('../controllers/auth');
const { requireAuth, requireRole } = require('../middleware/auth');
const { registerValidator, loginValidator } = require('../validators/auth');

const router = express.Router();

/**
 * @swagger
 * tags:
 *   - name: Auth
 *     description: Authentication and session endpoints
 */

/**
 * @swagger
 * components:
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 *   schemas:
 *     AuthUser:
 *       type: object
 *       properties:
 *         id: { type: string, example: "b3e4a6fa-1b25-4bfa-b8e6-6f3b1e1c0a11" }
 *         email: { type: string, example: "user@example.com" }
 *         name: { type: string, example: "Normal User" }
 *         role: { type: string, example: "user" }
 *         roles:
 *           type: array
 *           items: { type: string }
 *           example: ["user"]
 */

/**
 * @swagger
 * /auth/register:
 *   post:
 *     tags: [Auth]
 *     summary: Register a new user (defaults to role "user")
 *     description: Creates a new user with hashed password. Optionally sets an HttpOnly refresh token cookie if enabled.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password, name]
 *             properties:
 *               email: { type: string, format: email }
 *               password: { type: string, format: password, minLength: 8 }
 *               name: { type: string }
 *     responses:
 *       201:
 *         description: User registered (and logged in) successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken: { type: string }
 *                 user: { $ref: '#/components/schemas/AuthUser' }
 *       409:
 *         description: Email already registered
 */
router.post('/register', registerValidator(), authController.register.bind(authController));

/**
 * @swagger
 * /auth/login:
 *   post:
 *     tags: [Auth]
 *     summary: Login with email/password
 *     description: Returns a JWT access token. May also set an HttpOnly refresh token cookie if enabled.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email: { type: string, format: email }
 *               password: { type: string, format: password }
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken: { type: string }
 *                 user: { $ref: '#/components/schemas/AuthUser' }
 *       401:
 *         description: Invalid email or password
 */
router.post('/login', loginValidator(), authController.login.bind(authController));

/**
 * @swagger
 * /auth/logout:
 *   post:
 *     tags: [Auth]
 *     summary: Logout (revokes refresh token cookie, if present)
 *     responses:
 *       200:
 *         description: Logged out
 */
router.post('/logout', authController.logout.bind(authController));

/**
 * @swagger
 * /auth/me:
 *   get:
 *     tags: [Auth]
 *     summary: Get current authenticated user
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Current user
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user: { $ref: '#/components/schemas/AuthUser' }
 *       401:
 *         description: Missing/invalid token
 */
router.get('/me', requireAuth, authController.me.bind(authController));

/**
 * @swagger
 * /auth/protected:
 *   get:
 *     tags: [Auth]
 *     summary: Example protected route (any authenticated user)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: OK
 *       401:
 *         description: Unauthorized
 */
router.get('/protected', requireAuth, (req, res) => {
  res.json({ message: 'You are authenticated.', auth: req.auth });
});

/**
 * @swagger
 * /auth/admin-only:
 *   get:
 *     tags: [Auth]
 *     summary: Example admin-only protected route
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: OK
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Forbidden
 */
router.get('/admin-only', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ message: 'You are an admin.', auth: req.auth });
});

module.exports = router;
