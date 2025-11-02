import express from "express";
import { authLogin, authLogout, authMe, authRefreshToken, authRegister, authResetPasswordConfirm, authResetPasswordRequest } from "../controllers/userAuthController.js";

const router = express.Router();

router.post("/login", authLogin);
router.post("/register", authRegister);
router.post("/logout", authLogout);

router.get("/me", authMe);

router.post("/refresh-token", authRefreshToken)

router.post("/reset-password/request", authResetPasswordRequest);
router.post("/reset-password/confirm", authResetPasswordConfirm);

export default router;
