import express from "express";
import { authLogin, authLogout, authMe, authRefreshToken, authRegister, authResetPasswordConfirm, authResetPasswordRequest } from "../controllers/userAuthController.js";
import { authenticate } from "../middleware/userAuthMiddleware.js";

const router = express.Router();

router.post("/login", authLogin);
router.post("/register", authRegister);
router.post("/logout", authLogout);

router.get("/me", authenticate, authMe);

router.post("/refresh-token", authenticate, authRefreshToken)

router.post("/reset-password/request", authenticate, authResetPasswordRequest);
router.post("/reset-password/confirm", authenticate, authResetPasswordConfirm);

export default router;
