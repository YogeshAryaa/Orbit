import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import User from '../models/User.js';
import DeviceKey from '../models/DeviceKey.js';
import { ApiError } from '../utils/ApiError.js';
import { getSession } from '../services/tokenService.js';

export async function requireAuth(req, res, next) {
  try {
    const h = req.headers.authorization || '', token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) throw new ApiError(401, 'Authentication required');
    const p = jwt.verify(token, env.JWT_SECRET);
    const session = await getSession(p.sid, p.sub);
    if (!session) throw new ApiError(401, 'Session revoked or expired');
    const user = await User.findById(p.sub).select('-passwordHash');
    if (!user || user.status !== 'active') throw new ApiError(401, 'Invalid authentication');

    const deviceId = req.headers['x-device-id'] || p.deviceId;
    const enrolling = req.method === 'POST' && req.path === '/devices';
    if (!p.deviceId || !deviceId || deviceId !== p.deviceId || deviceId !== session.deviceId) {
      throw new ApiError(401, 'This session is not bound to an authorized device');
    }
    const dev = await DeviceKey.findOne({ user: user._id, deviceId });
    if (!dev && !enrolling) throw new ApiError(401, 'Device is not enrolled');
    if (dev) {
      if (dev.status === 'revoked' || !enrolling && dev.sessionId && dev.sessionId !== p.sid) {
        throw new ApiError(401, 'This device session has been revoked or replaced');
      }
      const pendingRead = req.method === 'GET' && (
        req.path === '/devices' ||
        (req.baseUrl === '/api/users' && req.path === '/me')
      );
      if (dev.linkStatus === 'pending' && !pendingRead && !enrolling) {
        throw new ApiError(403, 'This device is awaiting primary-device approval');
      }
      req.device = dev;
    }
    req.deviceId = deviceId;

    req.user = user;
    req.token = token;
    req.sessionId = p.sid;
    req.tokenExp = p.exp;
    next();
  } catch (e) {
    next(e instanceof ApiError ? e : new ApiError(401, 'Invalid or expired token'));
  }
}
