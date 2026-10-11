import jwt from 'jsonwebtoken';
import { randomUUID } from 'node:crypto';
import { env } from '../config/env.js';
import { getRedis } from '../config/redis.js';

// Redis-backed session records are shared by every API/socket instance. Memory fallback is development-only.
const memorySessions = new Map();
const key = (sid) => `${env.SESSION_PREFIX}${sid}`;
function expiresInSeconds(value) {
  if (typeof value === 'number') return value;
  const m = String(value).match(/^(\d+)(s|m|h|d)$/);
  if (!m) return 7 * 24 * 3600;
  return Number(m[1]) * ({ s: 1, m: 60, h: 3600, d: 86400 }[m[2]]);
}
export async function createSessionToken(userId) {
  const sid = randomUUID();
  const ttl = expiresInSeconds(env.JWT_EXPIRES_IN);
  const session = JSON.stringify({ userId: String(userId), createdAt: Date.now() });
  const redis = getRedis();
  if (redis) await redis.set(key(sid), session, { EX: ttl });
  else memorySessions.set(sid, { value: session, expiresAt: Date.now() + ttl * 1000 });
  const token = jwt.sign({ sub: String(userId), sid }, env.JWT_SECRET, { expiresIn: ttl });
  return { token, expiresIn: ttl };
}
export async function isSessionActive(sid, userId) {
  if (!sid) return false;
  const redis = getRedis();
  let raw;
  if (redis) raw = await redis.get(key(sid));
  else {
    const record = memorySessions.get(sid);
    if (record && record.expiresAt > Date.now()) raw = record.value;
    else memorySessions.delete(sid);
  }
  if (!raw) return false;
  try { return JSON.parse(raw).userId === String(userId); } catch { return false; }
}
export async function revokeSession(sid) {
  if (!sid) return;
  const redis = getRedis();
  if (redis) await redis.del(key(sid));
  else memorySessions.delete(sid);
}
export async function revokeAllUserSessions(userId) {
  const redis = getRedis();
  if (redis) {
    // Session records use a prefix; scan avoids blocking Redis with KEYS.
    for await (const k of redis.scanIterator({ MATCH: `${env.SESSION_PREFIX}*`, COUNT: 250 })) {
      const raw = await redis.get(k);
      if (raw) { try { if (JSON.parse(raw).userId === String(userId)) await redis.del(k); } catch {} }
    }
  } else {
    for (const [sid, record] of memorySessions) { try { if (JSON.parse(record.value).userId === String(userId)) memorySessions.delete(sid); } catch {} }
  }
}
export async function isRevoked(sid, userId) { return !(await isSessionActive(sid, userId)); }
