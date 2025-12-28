import { config } from 'dotenv';
config();

const serverConfig = Object.freeze({
  PORT: parseInt(process.env.PORT || '7100'),
  MODE: process.env.NODE_ENV || 'production',
  DATABASE_URL: process.env.DATABASE_URL,
});

const clientUrlConfig = Object.freeze({
  WEB: {
    URL: process.env.CLIENT_WEB_BASE_URL || 'http://localhost:3000',
    PATHS: {
      CHANGE_PASSWORD: process.env.CLIENT_WEB_CHANGE_PASSWORD_PATH || '/change-password',
    },
  },
  ADMIN: {
    URL: process.env.CLIENT_ADMIN_BASE_URL || 'http://localhost:5173',
    PATHS: {
      CHANGE_PASSWORD:
        process.env.CLIENT_ADMIN_CHANGE_PASSWORD_PATH || '/change-password',
    },
  },
});

const rateLimitConfig = Object.freeze({
  GLOBAL_LIMIT_WINDOW: parseInt(process.env.GLOBAL_LIMIT_WINDOW || `${15 * 60 * 1000}`), // 15 minutes
  GLOBAL_LIMIT_MAX: parseInt(process.env.GLOBAL_LIMIT_MAX || '100'),
});

const jwtConfig = Object.freeze({
  JWT_ISSUER: process.env.JWT_ISSUER,
  JWT_AUD: process.env.JWT_AUD,
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '1h',
  JWT_TILE_EXPIRES_IN: process.env.JWT_TILE_EXPIRES_IN || '10m',
  JWT_REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
});

const keysConfig = Object.freeze({
  PUBLIC_KEY_PATH: process.env.PUBLIC_KEY_PATH,
  PRIVATE_KEY_PATH: process.env.PRIVATE_KEY_PATH,
});

const tileKeysConfig = Object.freeze({
  TILE_PUBLIC_KEY_PATH: process.env.TILE_PUBLIC_KEY_PATH,
  TILE_PRIVATE_KEY_PATH: process.env.TILE_PRIVATE_KEY_PATH,
});

const bcryptConfig = Object.freeze({
  BCRYPT_ROUNDS: parseInt(process.env.BCRYPT_ROUNDS || '12'),
});

const emailSendingConfig = Object.freeze({
  EMAIL_SENDING_KEY: process.env.EMAIL_SENDING_KEY,
  EMAIL_API_URL: process.env.EMAIL_API_URL,
  EMAIL_USERNAME: process.env.EMAIL_USERNAME,
  EMAIL_DOMAIN: process.env.EMAIL_DOMAIN,
  EMAIL_RESET_PASSWORD_TEMPLATE: process.env.EMAIL_RESET_PASSWORD_TEMPLATE,
});

export {
  serverConfig,
  rateLimitConfig,
  jwtConfig,
  keysConfig,
  tileKeysConfig,
  bcryptConfig,
  emailSendingConfig,
  clientUrlConfig,
};
