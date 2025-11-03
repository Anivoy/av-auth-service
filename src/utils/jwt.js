import fs from 'fs';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

import { jwtConfig, keysConfig } from '../config/env.js';

const PRIVATE_KEY = fs.readFileSync(keysConfig.PRIVATE_KEY_PATH, 'utf8');
const PUBLIC_KEY = fs.readFileSync(keysConfig.PUBLIC_KEY_PATH, 'utf8');

export function signAccessToken(payload, options = {}) {
  return jwt.sign(payload, PRIVATE_KEY, {
    algorithm: 'RS256',
    issuer: jwtConfig.JWT_ISSUER,
    audience: jwtConfig.JWT_AUD,
    expiresIn: jwtConfig.JWT_EXPIRES_IN,
    ...options,
  });
}

export function verifyAccessToken(token) {
  return jwt.verify(token, PUBLIC_KEY, {
    algorithms: ['RS256'],
    issuer: jwtConfig.JWT_ISSUER,
    audience: jwtConfig.JWT_AUD,
  });
}

export function randomToken(size = 64) {
  return crypto.randomBytes(size).toString('hex');
}

export function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}