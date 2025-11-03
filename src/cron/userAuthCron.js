import cron from "node-cron";
import prisma from "../db/index.js";
import dayjs from "dayjs";

import { logger } from "../config/logger.js";

async function cleanupTokens() {
  const now = dayjs();

  try {
    const deletedReset = await prisma.passwordReset.deleteMany({
      where: { expiresAt: { lt: now } },
    });

    const deletedRefresh = await prisma.refreshToken.deleteMany({
      where: {
        OR: [{ expiresAt: { lt: now } }, { revoked: true }],
      },
    });

    logger.info(
      `Deleted ${deletedReset.count} expired reset tokens.`
    );
    logger.info(
      `Deleted ${deletedRefresh.count} expired/revoked refresh tokens.`
    );
  } catch (err) {
    logger.error("Cleanup failed:", err);
  }
}

logger.info("Starting token cleanup job...");

cleanupTokens().then(() => logger.info("Initial cleanup complete."));

cron.schedule("0 0 * * *", () => {
  logger.info("Running cleanup at midnight...");
  cleanupTokens();
});
