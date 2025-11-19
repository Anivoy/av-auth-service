import { verifyAccessToken } from "../utils/jwt.js";
import { logger } from "../config/logger.js";
import prisma from "../db/index.js";

export async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No access token" });
  }

  const accessToken = authHeader.substring(7);

  try {
    const decoded = verifyAccessToken(accessToken);

    const user = await prisma.userAuth.findUnique({
      where: { id: decoded.sub },
    });

    if (!user) {
      logger.warn(`Auth failed: User with ID ${decoded.sub} not found.`);
      return res.status(404).json({ error: "User not found" });
    }

    if (user.isActive === false) {
      logger.warn(
        `Auth blocked: User ${user.email} (ID: ${user.id}) is inactive.`
      );
      return res.status(403).json({ error: "User is inactive" });
    }

    req.user = {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      role: user.role,
      isActive: user.isActive,
    };

    logger.info(`User ${user.email} (ID: ${user.id}) authenticated.`);

    next();
  } catch (err) {
    logger.warn(`Token validation failed: ${err.message}`);
    return res.status(401).json({ error: "Invalid token" });
  }
}
