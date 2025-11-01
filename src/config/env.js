import { config } from "dotenv";
config();

const serverConfig = Object.freeze({
  PORT: process.env.PORT || 5087
});

const rateLimitConfig = Object.freeze({
  GLOBAL_LIMIT_WINDOW: process.env.GLOBAL_LIMIT_WINDOW || 15 * 60 * 1000, // 15 minutes
  GLOBAL_LIMIT_MAX: process.env.GLOBAL_LIMIT_MAX || 100
})

export {
  serverConfig,
  rateLimitConfig
}