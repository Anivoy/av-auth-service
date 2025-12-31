import bcrypt from 'bcrypt';
import dayjs from 'dayjs';
import prisma from '../db/index.js';
import { signAccessToken, randomToken, sha256, signTileToken } from '../utils/jwt.js';
import { logger } from '../config/logger.js';
import durationToSeconds from '../utils/durationToSeconds.js';
import { jwtConfig, bcryptConfig, clientUrlConfig } from '../config/env.js';
import { sendResetPassword } from '../utils/sendResetPassword.js';
import { AppError } from '../utils/errorUtility.js';

async function register({ email, password, displayName, role = 'USER' }) {
  const existing = await prisma.userAuth.findUnique({ where: { email } });
  if (existing) {
    logger.info(
      `Auth registration attempt failed for email: ${email}. User already exists.`,
    );
    throw new AppError('User already exists', 409);
  }

  const hashed = await bcrypt.hash(password, bcryptConfig.BCRYPT_ROUNDS);
  const user = await prisma.userAuth.create({
    data: {
      email,
      password: hashed,
      displayName,
      role,
      isActive: role === 'USER' ? true : false,
    },
  });

  logger.info(`New user successfully registered for email: ${user.email}.`);
  return { id: user.id, email: user.email, displayName: user.displayName };
}

async function login({ email, password }) {
  const user = await prisma.userAuth.findUnique({ where: { email } });
  if (!user) {
    logger.warn(`Auth login attempt failed for non-existent email: ${email}.`);
    throw new AppError('Invalid credentials', 401);
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    logger.warn(`Auth login attempt failed: Invalid password for user ${email}.`);
    throw new AppError('Invalid credentials', 401);
  }

  if (!user.isActive) {
    logger.warn(`Auth login attempt failed: User ${email} hasn't been activated.`);
    throw new AppError('User not active', 403);
  }

  const accessToken = signAccessToken({
    sub: user.id,
    email: user.email,
    displayName: user.displayName,
    role: user.role,
    isActive: user.isActive,
  });

  const refreshToken = randomToken(32);
  const refreshTokenHash = sha256(refreshToken);
  const expiresAt = dayjs()
    .add(durationToSeconds(jwtConfig.JWT_REFRESH_EXPIRES_IN), 'second')
    .toDate();

  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      tokenHash: refreshTokenHash,
      expiresAt,
    },
  });

  logger.info(
    `User ${user.email} (ID: ${user.id}) successfully logged in and issued new tokens.`,
  );

  return {
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      role: user.role,
      isActive: user.isActive,
    },
  };
}

async function activate(userId) {
  const user = await prisma.userAuth.findUnique({ where: { id: userId } });
  if (!user) {
    logger.error(`User (ID: ${userId}) not found during auth activation.`);
    throw new AppError(`User not found`, 404);
  }

  if (user.isActive) {
    logger.error(`User (ID: ${userId}) is already active`);
    throw new AppError(`User is already active`, 400);
  }

  await prisma.userAuth.update({
    where: { id: userId },
    data: { isActive: true },
  });

  logger.info(`User (ID: ${userId}) has been activated.`);
  return { userId };
}

async function revoke(userId) {
  const result = await prisma.$transaction(async (t) => {
    const user = await t.userAuth.findUnique({ where: { id: userId } });
    if (!user) {
      logger.error(`User (ID: ${userId}) not found during auth revoke.`);
      throw new AppError('User not found', 404);
    }

    await t.userAuth.update({
      where: { id: userId },
      data: { isActive: false },
    });

    await t.refreshToken.updateMany({
      where: { userId },
      data: { revoked: true },
    });

    return { user };
  });

  const { user } = result;
  logger.info(`User ${user.email} (ID: ${user.id}) has been successfully revoked.`);
  return { userId: user.id };
}

async function setRole(userId, role) {
  const result = await prisma.$transaction(async (t) => {
    const user = await t.userAuth.findUnique({ where: { id: userId } });
    if (!user) {
      logger.error(`User (ID: ${userId}) not found during set role.`);
      throw new AppError('User not found', 404);
    }

    await t.userAuth.update({
      where: { id: userId },
      data: { role },
    });

    await t.refreshToken.updateMany({
      where: { userId },
      data: { revoked: true },
    });

    return { user };
  });

  const { user } = result;
  logger.info(`User ${user.email} (ID: ${user.id}) role has been set successfully.`);
  return { userId: user.id };
}

async function logout(refreshToken) {
  if (refreshToken) {
    const tokenHash = sha256(refreshToken);
    const stored = await prisma.refreshToken.findUnique({ where: { tokenHash } });
    if (stored) {
      await prisma.refreshToken.update({
        where: { id: stored.id },
        data: { revoked: true },
      });
      logger.info(
        `User (ID: ${stored.userId}) successfully revoked their refresh token upon logout.`,
      );
    } else {
      logger.warn(
        'Logout attempt with refresh token failed: Token hash not found in DB.',
      );
    }
  } else {
    logger.info('Logout request received without a refresh token in cookies.');
  }

  return null;
}

async function refreshToken(refreshToken) {
  if (!refreshToken) {
    throw new AppError('No refresh token', 401);
  }

  const tokenHash = sha256(refreshToken);
  const stored = await prisma.refreshToken.findUnique({ where: { tokenHash } });

  if (!stored) {
    throw new AppError('Invalid refresh token', 401);
  }

  if (stored.revoked) {
    logger.error(
      `Security Alert: Revoked refresh token reused! User ID: ${stored.userId}, Token ID: ${stored.id}. All associated tokens will be revoked.`,
    );
    throw new AppError('Invalid refresh token', 401);
  }

  if (stored.expiresAt < dayjs()) {
    logger.info(
      `Token refresh failed: Refresh token (ID: ${stored.id}) for user ${stored.userId} expired.`,
    );
    throw new AppError('Invalid refresh token', 401);
  }

  const newRefresh = randomToken(32);
  const newHash = sha256(newRefresh);
  const newExpires = dayjs()
    .add(durationToSeconds(jwtConfig.JWT_REFRESH_EXPIRES_IN), 'second')
    .toDate();

  const result = await prisma.$transaction(async (t) => {
    const created = await t.refreshToken.create({
      data: {
        userId: stored.userId,
        tokenHash: newHash,
        expiresAt: newExpires,
      },
    });

    await t.refreshToken.update({
      where: { id: stored.id },
      data: { revoked: true, replacedById: created.id },
    });

    logger.info(
      `Refresh token (ID: ${stored.id}) rotated for user ${stored.userId}. New token ID: ${created.id}.`,
    );

    const user = await t.userAuth.findUnique({ where: { id: stored.userId } });
    if (!user) {
      logger.error(
        `User (ID: ${stored.userId}) not found during token refresh, even though a valid refresh token exists.`,
      );
      throw new AppError('User not found', 404);
    }

    return { created, user };
  });

  const { user } = result;
  const newAccess = signAccessToken({ sub: user.id, email: user.email });

  logger.info(`New access token issued for user ${user.email} (ID: ${user.id}).`);

  return { accessToken: newAccess, refreshToken: newRefresh };
}

async function resetPasswordRequest({ email, client = 'web' }) {
  const parsedClient = client?.trim()?.toUpperCase();
  if (!Object.keys(clientUrlConfig).includes(parsedClient)) {
    logger.info(
      `Password reset requested from invalid or unkown client: ${client}. Returning success to prevent enumeration.`,
    );
  }

  const CLIENT_URL = clientUrlConfig?.[parsedClient];

  const user = await prisma.userAuth.findUnique({ where: { email } });
  if (!user) {
    logger.info(
      `Password reset requested for non-existent email: ${email}. Returning success to prevent enumeration.`,
    );
    return null;
  }

  const token = randomToken(32);
  const tokenHash = sha256(token);
  const expiresAt = dayjs().add(30, 'minute').toDate();

  await prisma.passwordReset.create({
    data: {
      userId: user.id,
      tokenHash,
      expiresAt,
    },
  });

  logger.info(
    `Password reset token generated and sent for user ${user.email} (ID: ${user.id}).`,
  );

  await sendResetPassword({
    name: user.displayName,
    recepient: user.email,
    resetUrlBase: `${CLIENT_URL.URL}${CLIENT_URL.PATHS.CHANGE_PASSWORD}`,
    token,
  });

  return null;
}

async function resetPasswordConfirm({ token, newPassword }) {
  const tokenHash = sha256(token);
  const reset = await prisma.passwordReset.findUnique({ where: { tokenHash } });

  if (!reset) {
    logger.warn('Password reset confirmation failed: Token hash not found in DB.');
    throw new AppError('Invalid or expired token', 400);
  }

  if (reset.used) {
    logger.warn(
      `Password reset confirmation failed: Token (ID: ${reset.id}) for user ${reset.userId} already used.`,
    );
    throw new AppError('Invalid or expired token', 400);
  }

  if (reset.expiresAt < dayjs()) {
    logger.info(
      `Password reset confirmation failed: Token (ID: ${reset.id}) for user ${reset.userId} expired.`,
    );
    throw new AppError('Invalid or expired token', 400);
  }

  const hashed = await bcrypt.hash(newPassword, bcryptConfig.BCRYPT_ROUNDS);
  await prisma.userAuth.update({
    where: { id: reset.userId },
    data: { password: hashed },
  });

  await prisma.passwordReset.update({
    where: { id: reset.id },
    data: { used: true },
  });

  await prisma.refreshToken.updateMany({
    where: { userId: reset.userId, revoked: false },
    data: { revoked: true },
  });

  logger.info(
    `User ${reset.userId} successfully reset their password. All active refresh tokens revoked.`,
  );

  return null;
}

async function getMe(userId) {
  const user = await prisma.userAuth.findUnique({ where: { id: userId } });
  if (!user) {
    logger.warn(
      `Auth check failed: User ID ${userId} from access token not found in DB.`,
    );
    throw new AppError('User not found', 404);
  }

  logger.info(
    `User ${user.email} (ID: ${user.id}) successfully authenticated with 'authMe'.`,
  );

  return { id: user.id, email: user.email, displayName: user.displayName };
}

async function generateTileToken(userId) {
  const payload = {
    sub: userId,
    aud: 'tile-server',
    scope: ['tiles:read'],
  };

  const token = signTileToken(payload);

  return {
    tileToken: token,
  };
}

export default {
  login,
  register,
  logout,
  activate,
  revoke,
  setRole,
  resetPasswordRequest,
  resetPasswordConfirm,
  refreshToken,
  getMe,
  generateTileToken,
};
