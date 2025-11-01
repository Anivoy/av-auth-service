import express from "express";
import serverUtilityRoutes from "./serverUtility.js";

const router = express.Router();

router.use("/utility", serverUtilityRoutes);

export default router;
