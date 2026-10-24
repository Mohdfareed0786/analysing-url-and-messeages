import fs from 'node:fs';
import path from 'node:path';
import { initializeApp, getApps } from 'firebase-admin/app';
import { getAuth, type DecodedIdToken } from 'firebase-admin/auth';
import type { Request, Response, NextFunction } from 'express';

const configPath = path.join(process.cwd(), 'firebase-applet-config.json');
const firebaseConfig = JSON.parse(fs.readFileSync(configPath, 'utf8')) as {
  projectId: string;
};

if (!getApps().length) {
  initializeApp({
    projectId: firebaseConfig.projectId,
  });
}

export const adminAuth = getAuth();

export interface AuthenticatedRequest extends Request {
  user?: DecodedIdToken;
}

export async function requireAuth(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({
      success: false,
      error: {
        code: 'UNAUTHORIZED',
        message: 'Authentication required. Missing Bearer token in Authorization header.',
      },
    });
    return;
  }

  const idToken = authHeader.slice('Bearer '.length).trim();
  if (!idToken) {
    res.status(401).json({
      success: false,
      error: {
        code: 'EMPTY_TOKEN',
        message: 'Authentication required. Empty Bearer token.',
      },
    });
    return;
  }

  try {
    const decoded = await adminAuth.verifyIdToken(idToken);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Firebase token verification error:', err);
    res.status(401).json({
      success: false,
      error: {
        code: 'INVALID_TOKEN',
        message: 'Invalid or expired authentication session. Please sign in again.',
      },
    });
  }
}
