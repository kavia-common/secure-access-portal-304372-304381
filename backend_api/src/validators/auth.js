const { body } = require('express-validator');

// PUBLIC_INTERFACE
function registerValidator() {
  /** Express-validator chain for POST /auth/register */
  return [
    body('email').isEmail().withMessage('Valid email is required.').normalizeEmail(),
    body('password')
      .isString()
      .isLength({ min: 8, max: 72 })
      .withMessage('Password must be 8-72 characters.'),
    body('name').isString().trim().isLength({ min: 1, max: 120 }).withMessage('Name is required.'),
  ];
}

// PUBLIC_INTERFACE
function loginValidator() {
  /** Express-validator chain for POST /auth/login */
  return [
    body('email').isEmail().withMessage('Valid email is required.').normalizeEmail(),
    body('password').isString().isLength({ min: 1, max: 72 }).withMessage('Password is required.'),
  ];
}

module.exports = {
  registerValidator,
  loginValidator,
};
