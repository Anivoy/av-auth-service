import userAuthService from '../services/userAuthService.js';
import { setRefreshCookie, clearAuthCookies } from '../utils/cookie.js';
import {
  registerSchema,
  loginSchema,
  resetPasswordRequestSchema,
  resetPasswordConfirmSchema,
  idParamSchema,
  setRoleSchema,
} from '../validations/userAuthValidation.js';

export async function authRegister(req, res, next) {
  try {
    const data = registerSchema.parse(req.body);
    const result = await userAuthService.register(data);

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: result,
    });
  } catch (error) {
    next(error);
  }
}

export async function authRegisterAdmin(req, res, next) {
  try {
    const data = registerSchema.parse(req.body);
    const result = await userAuthService.register({ ...data, role: 'ADMIN' });

    res.status(201).json({
      success: true,
      message: 'Admin registered successfully',
      data: result,
    });
  } catch (error) {
    next(error);
  }
}

export async function authLogin(req, res, next) {
  try {
    const data = loginSchema.parse(req.body);
    const result = await userAuthService.login(data);

    setRefreshCookie(res, result.refreshToken);

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        accessToken: result.accessToken,
        user: result.user,
      },
    });
  } catch (error) {
    next(error);
  }
}

export async function authActivate(req, res, next) {
  try {
    const validatedId = idParamSchema.parse(req.params.id);
    const result = await userAuthService.activate(validatedId);

    res.status(200).json({
      success: true,
      message: 'User activated successfully',
      data: result,
    });
  } catch (error) {
    next(error);
  }
}

export async function authRevoke(req, res, next) {
  try {
    const validatedId = idParamSchema.parse(req.params.id);
    const result = await userAuthService.revoke(validatedId);

    res.json({
      success: true,
      message: 'User revoked successfully',
      data: result,
    });
  } catch (error) {
    next(error);
  }
}

export async function authSetRole(req, res, next) {
  try {
    const validatedId = idParamSchema.parse(req.params.id);
    const data = setRoleSchema.parse(req.body);
    const result = await userAuthService.setRole(validatedId, data.role);

    res.json({
      success: true,
      message: 'User role has been set successfully',
      data: result,
    });
  } catch (error) {
    next(error);
  }
}

export async function authLogout(req, res, next) {
  try {
    const refreshToken = req.cookies?.refresh_token;
    await userAuthService.logout(refreshToken);

    clearAuthCookies(res);

    res.json({
      success: true,
      message: 'Logout successful',
    });
  } catch (error) {
    clearAuthCookies(res);
    next(error);
  }
}

export async function authRefreshToken(req, res, next) {
  try {
    const refreshToken = req.cookies?.refresh_token;
    const result = await userAuthService.refreshToken(refreshToken);

    setRefreshCookie(res, result.refreshToken);

    res.status(200).json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        accessToken: result.accessToken,
      },
    });
  } catch (error) {
    clearAuthCookies(res);
    next(error);
  }
}

export async function authResetPasswordRequest(req, res, next) {
  try {
    const data = resetPasswordRequestSchema.parse(req.body);
    await userAuthService.resetPasswordRequest(data);

    res.json({
      success: true,
      message: 'Password reset email sent',
    });
  } catch (error) {
    next(error);
  }
}

export async function authResetPasswordConfirm(req, res, next) {
  try {
    const data = resetPasswordConfirmSchema.parse(req.body);
    await userAuthService.resetPasswordConfirm(data);

    clearAuthCookies(res);

    res.status(200).json({
      success: true,
      message: 'Password reset successful',
    });
  } catch (error) {
    next(error);
  }
}

export async function authMe(req, res, next) {
  try {
    const { id } = req.user;
    const result = await userAuthService.getMe(id);

    res.json({
      success: true,
      message: 'User retrieved successfully',
      data: result,
    });
  } catch (error) {
    next(error);
  }
}

export async function authGenerateTileToken(req, res, next) {
  const { id, isActive } = req.user;

  try {
    const result = await userAuthService.generateTileToken(id, isActive);

    res.json({
      success: true,
      message: 'Tile token has been generated successfully',
      data: result,
    });
  } catch (error) {
    next(error);
  }
}