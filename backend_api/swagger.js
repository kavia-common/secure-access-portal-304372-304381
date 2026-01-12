const swaggerJSDoc = require('swagger-jsdoc');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Secure Access Portal API',
      version: '1.0.0',
      description: 'Express API with PostgreSQL-backed authentication and role-based access control (RBAC).',
    },
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
    security: [
      { bearerAuth: [] },
    ],
  },
  apis: ['./src/routes/*.js', './src/routes/**/*.js'],
};

const swaggerSpec = swaggerJSDoc(options);
module.exports = swaggerSpec;
