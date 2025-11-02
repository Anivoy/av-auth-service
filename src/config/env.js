import { config } from "dotenv";
config();

const serverConfig = Object.freeze({
  PORT: parseInt(process.env.PORT || "5087"),
  DATABASE_URL: process.env.DATABASE_URL
});

const rateLimitConfig = Object.freeze({
  GLOBAL_LIMIT_WINDOW: parseInt(process.env.GLOBAL_LIMIT_WINDOW || `${15 * 60 * 1000}`), // 15 minutes
  GLOBAL_LIMIT_MAX: parseInt(process.env.GLOBAL_LIMIT_MAX || "100")
})

const jwtConfig = Object.freeze({
  JWT_ISSUER: process.env.JWT_ISSUER,
  JWT_AUD: process.env.JWT_AUD,
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || "1h",
  JWT_REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN || "7d"
})

const keysConfig = Object.freeze({
  PUBLIC_KEY_PATH: process.env.PUBLIC_KEY_PATH,
  PRIVATE_KEY_PATH: process.env.PRIVATE_KEY_PATH
})

const bcryptConfig = Object.freeze({
  BCRYPT_ROUNDS: parseInt(process.env.BCRYPT_ROUNDS || "12")
})

export {
  serverConfig,
  rateLimitConfig,
  jwtConfig,
  keysConfig,
  bcryptConfig
}