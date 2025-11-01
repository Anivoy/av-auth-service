import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

import { stream } from "./config/logger.js";
import morgan from "morgan";

import { rateLimitConfig } from "./config/env.js";

import routes from "./routes/index.js";

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan("combined", { stream }));

app.use(
  rateLimit({
    windowMs: rateLimitConfig.GLOBAL_LIMIT_WINDOW,
    max: rateLimitConfig.GLOBAL_LIMIT_MAX,
  })
);

app.use("/api", routes);

app.get("/", (req, res) => {
  res.json({ status: "ok", message: "[Anime Scape] Auth service is up" });
});

export default app;
