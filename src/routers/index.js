import express from "express";
import serverUtilityRoutes from "./serverUtility.js";
import userAuthRouter from "./userAuthRouter.js"

const router = express.Router();

router.use("/utility", serverUtilityRoutes);
router.use("/auth", userAuthRouter)

export default router;
