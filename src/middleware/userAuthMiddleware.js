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
      logger.warn(
        `Auth check failed: User ID ${decoded.sub} from access token not found in DB.`
      );
      return res.status(404).json({ error: "User not found" });
    }

    req.user = {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
    };

    logger.info(
      `User ${user.email} (ID: ${user.id}) successfully authenticated.`
    );

    next();
  } catch (err) {
    logger.warn(
      `Access token validation failed: ${err.message}. Token was likely expired or malformed.`
    );
    return res.status(401).json({ error: "Invalid token" });
  }
}
