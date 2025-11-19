import { z } from 'zod';

const registerSchema = z.object({
  email: z.email('Invalid email format'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  displayName: z.string().optional(),
  role: z.enum(['USER', 'ADMIN']).optional(),
});

const loginSchema = z.object({
  email: z.email('Invalid email format'),
  password: z.string().min(1, 'Password is required'),
});

const idParamSchema = z.uuid('Invalid ID format');

const resetPasswordRequestSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  email: z.email('Invalid email format'),
  resetUrl: z.string().min(1, 'Reset password url is required'),
});

const resetPasswordConfirmSchema = z.object({
  token: z.string().min(1, 'Token is required'),
  newPassword: z.string().min(8, 'Password must be at least 8 characters'),
});

const setRoleSchema = z.object({
  role: z.enum(['ADMIN', 'USER']),
});

export {
  idParamSchema,
  registerSchema,
  loginSchema,
  resetPasswordConfirmSchema,
  resetPasswordRequestSchema,
  setRoleSchema,
};
