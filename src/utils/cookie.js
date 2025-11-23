import { jwtConfig } from "../config/env.js";
import durationToSeconds from "./durationToSeconds.js";

const isProd = process.env.NODE_ENV === "production";

export function setAccessCookie(res, token) {
  res.cookie("access_token", token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? "none" : "lax",
    domain: isProd ? process.env.COOKIE_DOMAIN : "localhost",
    path: "/",
    maxAge: durationToSeconds(jwtConfig.JWT_EXPIRES_IN) * 1000
  });
}

export function setRefreshCookie(res, token) {
  res.cookie("refresh_token", token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? "none" : "lax",
    domain: isProd ? process.env.COOKIE_DOMAIN : "localhost",
    path: "/",
    maxAge: durationToSeconds(jwtConfig.JWT_REFRESH_EXPIRES_IN) * 1000
  });
}

export function clearAuthCookies(res) {
  res.clearCookie("access_token", {
    domain: isProd ? process.env.COOKIE_DOMAIN : undefined,
    path: "/",
  });
  res.clearCookie("refresh_token", {
    domain: isProd ? process.env.COOKIE_DOMAIN : undefined,
    path: "/",
  });
}
