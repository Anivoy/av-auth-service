import bcrypt from 'bcrypt';
import dayjs from 'dayjs';
import prisma from '../db/index.js';
import { signAccessToken, verifyAccessToken, randomToken, sha256 } from '../utils/jwt.js';

import { logger } from '../config/logger.js';
import durationToSeconds from '../utils/durationToSeconds.js';
import { setRefreshCookie, clearAuthCookies } from '../utils/cookie.js';

import z from 'zod';
import { registerSchema, loginSchema, resetPasswordRequestSchema, resetPasswordConfirmSchema } from '../validations/userAuthValidation.js';

import dotenv from 'dotenv';
import { jwtConfig, bcryptConfig } from '../config/env.js';
dotenv.config();

export async function authRegister(req, res) {
  try {
    const { email, password, displayName } = registerSchema.parse(req.body);

    const existing = await prisma.userAuth.findUnique({ where: { email } });
    if (existing) {
      logger.info(`Auth registration attempt failed for email: ${email}. User already exists.`);
      return res.status(409).json({ error: 'User already exists' });
    }

    const hashed = await bcrypt.hash(password, bcryptConfig.BCRYPT_ROUNDS);
    const user = await prisma.userAuth.create({
      data: { email, password: hashed, displayName }
    });

    logger.info(`New user successfully registered for email: ${user.email}.`);
    return res.status(201).json({ id: user.id, email: user.email, displayName: user.displayName });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation failed', details: error.errors });
    }
    logger.error(`Error during user registration for email ${email}: ${error.message}`);
    return res.status(500).json({ error: 'An unexpected error occurred during registration.' });
  }
}

export async function authLogin(req, res) {
  try {
    const { email, password } = loginSchema.parse(req.body);

    const user = await prisma.userAuth.findUnique({ where: { email } });
    if (!user) {
      logger.warn(`Auth login attempt failed for non-existent email: ${email}.`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      logger.warn(`Auth login attempt failed: Invalid password for user ${email}.`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const accessToken = signAccessToken({ sub: user.id, email: user.email });

    const refreshToken = randomToken(32);
    const refreshTokenHash = sha256(refreshToken);
    const expiresAt = dayjs().add(durationToSeconds(jwtConfig.JWT_REFRESH_EXPIRES_IN), 'second').toDate();

    await prisma.refreshToken.create({
      data: {
        userId: user.id,
        tokenHash: refreshTokenHash,
        expiresAt
      }
    });

    setRefreshCookie(res, refreshToken);

    logger.info(`User ${user.email} (ID: ${user.id}) successfully logged in and issued new tokens.`);
    return res.json({
      accessToken,
      user: { id: user.id, email: user.email, displayName: user.displayName }
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation failed', details: error.errors });
    }
    logger.error(`Error during user login for email ${email}: ${error.message}`);
    return res.status(500).json({ error: 'An unexpected error occurred during login.' });
  }
}

export async function authLogout(req, res) {
  const refreshToken = req.cookies?.refresh_token;

  try {
    if (refreshToken) {
      const tokenHash = sha256(refreshToken);
      const stored = await prisma.refreshToken.findUnique({ where: { tokenHash } });
      if (stored) {
        await prisma.refreshToken.update({ where: { id: stored.id }, data: { revoked: true } });
        logger.info(`User (ID: ${stored.userId}) successfully revoked their refresh token upon logout.`);
      } else {
        logger.warn('Logout attempt with refresh token failed: Token hash not found in DB.');
      }
    } else {
      logger.info('Logout request received without a refresh token in cookies.');
    }

    clearAuthCookies(res);
    return res.json({ ok: true });
  } catch (error) {
    logger.error(`Error during user logout: ${error.message}`);
    clearAuthCookies(res);
    return res.status(500).json({ error: 'An unexpected error occurred during logout.' });
  }
}

export async function authRefreshToken(req, res) {
  const refreshToken = req.cookies?.refresh_token;
  if (!refreshToken) {
    return res.status(401).json({ error: 'No refresh token' });
  }

  try {
    const tokenHash = sha256(refreshToken);
    let stored = await prisma.refreshToken.findUnique({ where: { tokenHash } });

    if (!stored) {
      clearAuthCookies(res);
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    if (stored.revoked) {
      logger.error(`Security Alert: Revoked refresh token reused! User ID: ${stored.userId}, Token ID: ${stored.id}. All associated tokens will be revoked.`);
      clearAuthCookies(res);
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    if (stored.expiresAt < dayjs()) {
      logger.info(`Token refresh failed: Refresh token (ID: ${stored.id}) for user ${stored.userId} expired.`);
      clearAuthCookies(res);
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const newRefresh = randomToken(32);
    const newHash = sha256(newRefresh);
    const newExpires = dayjs().add(durationToSeconds(jwtConfig.JWT_REFRESH_EXPIRES_IN), 'second').toDate();

    const created = await prisma.refreshToken.create({
      data: {
        userId: stored.userId,
        tokenHash: newHash,
        expiresAt: newExpires,
      }
    });

    await prisma.refreshToken.update({
      where: { id: stored.id },
      data: { revoked: true, replacedById: created.id }
    });
    logger.info(`Refresh token (ID: ${stored.id}) rotated for user ${stored.userId}. New token ID: ${created.id}.`);

    const user = await prisma.userAuth.findUnique({ where: { id: stored.userId } });
    if (!user) {
      logger.error(`User (ID: ${stored.userId}) not found during token refresh, even though a valid refresh token exists.`);
      clearAuthCookies(res);
      return res.status(404).json({ error: 'User not found' });
    }
    const newAccess = signAccessToken({ sub: user.id, email: user.email });

    setRefreshCookie(res, newRefresh);

    logger.info(`New access token issued for user ${user.email} (ID: ${user.id}).`);
    return res.status(200).json({ accessToken: newAccess });
  } catch (error) {
    logger.error(`Error during token refresh: ${error.message}`);
    return res.status(500).json({ error: 'An unexpected error occurred during token refresh.' });
  }
}

export async function authResetPasswordRequest(req, res) {
  try {
    const { email } = resetPasswordRequestSchema.parse(req.body);

    const user = await prisma.userAuth.findUnique({ where: { email } });
    if (!user) {
      logger.info(`Password reset requested for non-existent email: ${email}. Returning success to prevent enumeration.`);
      return res.status(200).json({ ok: true });
    }

    const token = randomToken(32);
    const tokenHash = sha256(token);
    const expiresAt = dayjs().add(30, 'minute').toDate();

    await prisma.passwordReset.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt
      }
    });

    logger.info(`Password reset token generated for user ${user.email} (ID: ${user.id}).`);
    // TODO: send email with reset link
    // For dev only: return token (do not do this in prod)
    return res.status(200).json({ ok: true, resetToken: token });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation failed', details: error.errors });
    }
    logger.error(`Error during password reset request for email ${email}: ${error.message}`);
    return res.status(500).json({ error: 'An unexpected error occurred during password reset request.' });
  }
}

export async function authResetPasswordConfirm(req, res) {
  try {
    const { token, newPassword } = resetPasswordConfirmSchema.parse(req.body);

    const tokenHash = sha256(token);
    const reset = await prisma.passwordReset.findUnique({ where: { tokenHash } });

    if (!reset) {
      logger.warn('Password reset confirmation failed: Token hash not found in DB.');
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    if (reset.used) {
      logger.warn(`Password reset confirmation failed: Token (ID: ${reset.id}) for user ${reset.userId} already used.`);
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    if (reset.expiresAt < dayjs()) {
      logger.info(`Password reset confirmation failed: Token (ID: ${reset.id}) for user ${reset.userId} expired.`);
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const hashed = await bcrypt.hash(newPassword, bcryptConfig.BCRYPT_ROUNDS);
    await prisma.userAuth.update({ where: { id: reset.userId }, data: { password: hashed } });
    await prisma.passwordReset.update({ where: { id: reset.id }, data: { used: true } });

    await prisma.refreshToken.updateMany({
      where: { userId: reset.userId, revoked: false },
      data: { revoked: true }
    });

    logger.info(`User ${reset.userId} successfully reset their password. All active refresh tokens revoked.`);

    clearAuthCookies(res);
    return res.status(200).json({ ok: true });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ error: 'Validation failed', details: error.errors });
    }
    logger.error(`Error during password reset confirmation: ${error.message}`);
    return res.status(500).json({ error: 'An unexpected error occurred during password reset confirmation.' });
  }
}

export async function authMe(req, res) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No access token' });
  }

  const accessToken = authHeader.substring(7);

  try {
    const decoded = verifyAccessToken(accessToken);

    const user = await prisma.userAuth.findUnique({ where: { id: decoded.sub } });
    if (!user) {
      logger.warn(`Auth check failed: User ID ${decoded.sub} from access token not found in DB.`);
      return res.status(404).json({ error: 'User not found' });
    }

    logger.info(`User ${user.email} (ID: ${user.id}) successfully authenticated with 'authMe'.`);
    return res.json({ id: user.id, email: user.email, displayName: user.displayName });
  } catch (err) {
    logger.warn(`Access token validation failed: ${err.message}. Token was likely expired or malformed.`);
    return res.status(401).json({ error: 'Invalid token' });
  }
}