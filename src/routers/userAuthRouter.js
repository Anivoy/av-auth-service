import express from "express";
import { authActivate, authLogin, authLogout, authMe, authRefreshToken, authRegister, authRegisterAdmin, authResetPasswordConfirm, authResetPasswordRequest, authRevoke, authSetRole } from "../controllers/userAuthController.js";
import { authenticate } from "../middleware/userAuthMiddleware.js";
import { authorizeRoles } from "../middleware/authorizeRolesMiddleware.js";

const router = express.Router();

router.post("/login", authLogin);
router.post("/register", authRegister);
router.post("/register-admin", authRegisterAdmin);
router.post("/logout", authLogout);
router.patch("/activate/id/:id", authenticate, authorizeRoles("ADMIN"), authActivate);
router.patch("/revoke/id/:id", authenticate, authorizeRoles("ADMIN"), authRevoke);
router.patch("/setrole/id/:id", authenticate, authorizeRoles("ADMIN"), authSetRole);

router.get("/me", authenticate, authMe);

router.post("/refresh-token", authenticate, authRefreshToken)

router.post("/reset-password/request", authResetPasswordRequest);
router.post("/reset-password/confirm", authResetPasswordConfirm);

export default router;
