import { jwtConfig } from "../config/env.js";
import durationToSeconds from "./durationToSeconds.js";

export function setAccessCookie(res, token) {
  res.cookie('access_token', token, {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === 'true',
    domain: process.env.COOKIE_DOMAIN || undefined,
    sameSite: process.env.COOKIE_SAME_SITE || 'lax',
    maxAge: durationToSeconds(jwtConfig.JWT_EXPIRES_IN) * 1000
  });
}

export function setRefreshCookie(res, token) {
  res.cookie('refresh_token', token, {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === 'true',
    domain: process.env.COOKIE_DOMAIN || undefined,
    sameSite: process.env.COOKIE_SAME_SITE || 'lax',
    maxAge: durationToSeconds(jwtConfig.JWT_REFRESH_EXPIRES_IN) * 1000
  });
}

export function clearAuthCookies(res) {
  res.clearCookie('access_token');
  res.clearCookie('refresh_token');
}
