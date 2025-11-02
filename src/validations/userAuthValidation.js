import { z } from 'zod';

const registerSchema = z.object({
  email: z.email('Invalid email format'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  displayName: z.string().optional()
});

const loginSchema = z.object({
  email: z.email('Invalid email format'),
  password: z.string().min(1, 'Password is required')
});

const resetPasswordRequestSchema = z.object({
  email: z.email('Invalid email format')
});

const resetPasswordConfirmSchema = z.object({
  token: z.string().min(1, 'Token is required'),
  newPassword: z.string().min(8, 'Password must be at least 8 characters')
});

export {
  registerSchema,
  loginSchema,
  resetPasswordConfirmSchema,
  resetPasswordRequestSchema
}