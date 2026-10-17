import DeviceKey from '../models/DeviceKey.js';
import Conversation from '../models/Conversation.js';
import Message from '../models/Message.js';
import { ApiError } from '../utils/ApiError.js';
import { ok } from '../utils/respond.js';
import { assertObjectId } from '../utils/ids.js';
import { parseDeviceInfo } from '../utils/deviceInfo.js';
import { revokeSession } from '../services/tokenService.js';

const clean = (d, includePrekeys = true) => ({
  userId: String(d.user),
  deviceId: d.deviceId,
  deviceName: d.deviceName || 'Web Browser',
  os: d.os || 'Unknown OS',
  browser: d.browser || 'Browser',
  deviceType: d.deviceType || 'browser',
  sessionId: d.sessionId || '',
  lastSeenAt: d.lastSeenAt,
  createdAt: d.createdAt,
  historyAllowed: d.historyAllowed !== false,
  newMessagesAllowed: d.newMessagesAllowed !== false,
  status: d.status || 'authorized',
  historyAllowedAt: d.historyAllowedAt || null,
  identityPublicKey: d.identityPublicKey,
  signedPreKeyPublic: d.signedPreKeyPublic,
  signedPreKeySignature: d.signedPreKeySignature,
  tabs: d.tabs || [],
  ...(includePrekeys ? { oneTimePreKeyCount: d.oneTimePreKeys?.length || 0 } : {})
});

export async function registerDeviceKeys(req, res) {
  const b = req.body || {};
  if (typeof b.deviceId !== 'string' || b.deviceId.length < 1 || b.deviceId.length > 100) {
    throw new ApiError(400, 'deviceId is required (1-100 characters)');
  }
  for (const k of ['identityPublicKey', 'signedPreKeyPublic', 'signedPreKeySignature']) {
    if (typeof b[k] !== 'string' || b[k].length < 20 || b[k].length > 4096) {
      throw new ApiError(400, `${k} is invalid`);
    }
  }
  if (!Array.isArray(b.oneTimePreKeys) || b.oneTimePreKeys.length > 500) {
    throw new ApiError(400, 'oneTimePreKeys must be an array with at most 500 entries');
  }

  const seen = new Set();
  for (const p of b.oneTimePreKeys) {
    if (!p || typeof p.keyId !== 'string' || p.keyId.length > 100 || typeof p.publicKey !== 'string' || p.publicKey.length < 20 || p.publicKey.length > 4096 || seen.has(p.keyId)) {
      throw new ApiError(400, 'Invalid or duplicate one-time prekey');
    }
    seen.add(p.keyId);
  }

  const parsed = parseDeviceInfo(req.headers['user-agent']);
  const deviceName = b.deviceName || parsed.deviceName;
  const os = b.os || parsed.os;
  const browser = b.browser || parsed.browser;
  const deviceType = b.deviceType || parsed.deviceType;
  const ipAddress = req.ip || req.connection?.remoteAddress || '';
  const userAgent = req.headers['user-agent'] || '';

  // Check if this device already exists
  let existingDoc = await DeviceKey.findOne({ user: req.user.id, deviceId: b.deviceId });

  let historyAllowed = true;
  let newMessagesAllowed = true;
  let status = 'authorized';
  let historyAllowedAt = null;

  if (existingDoc) {
    // Preserve existing permissions and status
    historyAllowed = existingDoc.historyAllowed !== false;
    newMessagesAllowed = existingDoc.newMessagesAllowed !== false;
    status = existingDoc.status || 'authorized';
    historyAllowedAt = existingDoc.historyAllowedAt;
  } else {
    // New device registration: check if this is user's first device
    const priorDevicesCount = await DeviceKey.countDocuments({
      user: req.user.id,
      deviceId: { $ne: b.deviceId },
      status: { $ne: 'revoked' }
    });

    if (priorDevicesCount > 0) {
      // Secondary device logging in: new messages only by default, historical requires explicit permission
      historyAllowed = false;
      newMessagesAllowed = true;
      status = 'authorized';
      historyAllowedAt = new Date();
    }
  }

  const doc = await DeviceKey.findOneAndUpdate(
    { user: req.user.id, deviceId: b.deviceId },
    {
      $set: {
        identityPublicKey: b.identityPublicKey,
        signedPreKeyPublic: b.signedPreKeyPublic,
        signedPreKeySignature: b.signedPreKeySignature,
        oneTimePreKeys: b.oneTimePreKeys,
        lastSeenAt: new Date(),
        deviceName,
        os,
        browser,
        deviceType,
        ipAddress,
        userAgent,
        sessionId: req.sessionId || '',
        historyAllowed,
        newMessagesAllowed,
        status,
        historyAllowedAt
      }
    },
    { upsert: true, new: true, runValidators: true }
  );

  ok(res, clean(doc), 'Public device keys registered');
}

export async function listMyDevices(req, res) {
  const ds = await DeviceKey.find({ user: req.user.id })
    .select('deviceId deviceName os browser deviceType sessionId lastSeenAt createdAt historyAllowed newMessagesAllowed status historyAllowedAt identityPublicKey signedPreKeyPublic signedPreKeySignature oneTimePreKeys.length tabs')
    .sort({ lastSeenAt: -1 });

  const currentDeviceId = req.headers['x-device-id'] || '';
  const result = ds.map(d => ({
    ...clean(d),
    isCurrentDevice: d.deviceId === currentDeviceId,
    isCurrentSession: Boolean(req.sessionId && d.sessionId === req.sessionId)
  }));

  ok(res, result, 'Your registered devices');
}

export async function updateDevicePermissions(req, res) {
  const deviceId = String(req.params.deviceId || '');
  const doc = await DeviceKey.findOne({ user: req.user.id, deviceId });
  if (!doc) throw new ApiError(404, 'Device not found');

  const policy = req.body.policy;
  if (policy === 'allow_all') {
    doc.historyAllowed = true;
    doc.newMessagesAllowed = true;
    doc.status = 'authorized';
    doc.historyAllowedAt = null;
  } else if (policy === 'new_messages_only') {
    doc.historyAllowed = false;
    doc.newMessagesAllowed = true;
    doc.status = 'authorized';
    if (!doc.historyAllowedAt) doc.historyAllowedAt = new Date();
  } else if (policy === 'block') {
    doc.historyAllowed = false;
    doc.newMessagesAllowed = false;
    doc.status = 'fully_blocked';
  } else {
    // Explicit discrete flags
    if (req.body.historyAllowed !== undefined) {
      doc.historyAllowed = Boolean(req.body.historyAllowed);
      if (doc.historyAllowed) doc.historyAllowedAt = null;
      else if (!doc.historyAllowedAt) doc.historyAllowedAt = new Date();
    }
    if (req.body.newMessagesAllowed !== undefined) {
      doc.newMessagesAllowed = Boolean(req.body.newMessagesAllowed);
    }
    if (!doc.newMessagesAllowed && !doc.historyAllowed) {
      doc.status = 'fully_blocked';
    } else if (!doc.historyAllowed) {
      doc.status = 'history_blocked';
    } else {
      doc.status = 'authorized';
    }
  }

  await doc.save();

  // Notify active sockets via Socket.IO
  const io = req.app.get('io');
  if (io) {
    io.to(`user:${req.user.id}`).emit('device:permission_updated', {
      deviceId: doc.deviceId,
      historyAllowed: doc.historyAllowed,
      newMessagesAllowed: doc.newMessagesAllowed,
      status: doc.status
    });
  }

  ok(res, clean(doc), 'Device permissions updated');
}

export async function revokeDevice(req, res) {
  const deviceId = String(req.params.deviceId || '');
  const doc = await DeviceKey.findOne({ user: req.user.id, deviceId });
  if (!doc) throw new ApiError(404, 'Device not found');

  doc.status = 'revoked';
  doc.historyAllowed = false;
  doc.newMessagesAllowed = false;
  await doc.save();

  // Invalidate session in Redis/memory
  if (doc.sessionId) {
    await revokeSession(doc.sessionId);
  }

  // Terminate any connected sockets for this device
  const io = req.app.get('io');
  if (io) {
    const sockets = await io.in(`user:${req.user.id}`).fetchSockets();
    for (const s of sockets) {
      if (s.deviceId === deviceId || s.sessionId === doc.sessionId || s.data?.sessionId === doc.sessionId) {
        s.emit('device:revoked', { deviceId });
        s.disconnect(true);
      }
    }
    io.to(`user:${req.user.id}`).emit('device:permission_updated', {
      deviceId: doc.deviceId,
      historyAllowed: false,
      newMessagesAllowed: false,
      status: 'revoked'
    });
  }

  ok(res, clean(doc), 'Device session and access revoked');
}

export async function deleteMyDevice(req, res) {
  const deviceId = String(req.params.deviceId || '');
  const doc = await DeviceKey.findOne({ user: req.user.id, deviceId });
  if (!doc) throw new ApiError(404, 'Device not found');

  if (doc.sessionId) {
    await revokeSession(doc.sessionId);
  }
  const result = await DeviceKey.deleteOne({ user: req.user.id, deviceId });
  if (!result.deletedCount) throw new ApiError(404, 'Device not found');

  const io = req.app.get('io');
  if (io) {
    const sockets = await io.in(`user:${req.user.id}`).fetchSockets();
    for (const s of sockets) {
      if (s.deviceId === deviceId || s.sessionId === doc.sessionId) {
        s.emit('device:revoked', { deviceId });
        s.disconnect(true);
      }
    }
  }

  ok(res, null, 'Device keys deleted and session revoked');
}

export async function syncTab(req, res) {
  const b = req.body || {};
  const deviceId = String(b.deviceId || req.headers['x-device-id'] || '');
  const tabId = String(b.tabId || '');
  if (!deviceId || !tabId) throw new ApiError(400, 'deviceId and tabId are required');

  const doc = await DeviceKey.findOne({ user: req.user.id, deviceId });
  if (!doc) throw new ApiError(404, 'Device not found');

  const title = String(b.title || 'Browser Tab').slice(0, 100);
  const status = ['active', 'restricted', 'closed'].includes(b.status) ? b.status : 'active';

  const existingTabIndex = (doc.tabs || []).findIndex(t => t.tabId === tabId);
  if (existingTabIndex >= 0) {
    doc.tabs[existingTabIndex].title = title;
    doc.tabs[existingTabIndex].lastActiveAt = new Date();
    doc.tabs[existingTabIndex].status = status;
  } else {
    doc.tabs.push({ tabId, title, lastActiveAt: new Date(), status });
  }

  // Prune tabs older than 7 days
  const sevenDaysAgo = new Date(Date.now() - 7 * 86400 * 1000);
  doc.tabs = doc.tabs.filter(t => t.lastActiveAt > sevenDaysAgo && t.status !== 'closed');

  await doc.save();
  ok(res, doc.tabs, 'Tab synchronized');
}

export async function updateTabStatus(req, res) {
  const deviceId = String(req.params.deviceId || '');
  const tabId = String(req.params.tabId || '');
  const status = req.body.status;
  if (!['active', 'restricted', 'closed'].includes(status)) {
    throw new ApiError(400, 'Invalid tab status');
  }

  const doc = await DeviceKey.findOne({ user: req.user.id, deviceId });
  if (!doc) throw new ApiError(404, 'Device not found');

  const tab = (doc.tabs || []).find(t => t.tabId === tabId);
  if (!tab) throw new ApiError(404, 'Tab not found');

  tab.status = status;
  tab.lastActiveAt = new Date();
  await doc.save();

  ok(res, doc.tabs, 'Tab status updated');
}

export async function authorizeHistoryEnvelopes(req, res) {
  const b = req.body || {};
  const targetDeviceId = String(b.targetDeviceId || '');
  const envelopes = Array.isArray(b.envelopes) ? b.envelopes : [];

  if (!targetDeviceId) throw new ApiError(400, 'targetDeviceId is required');
  if (!envelopes.length) throw new ApiError(400, 'No envelopes provided');

  // Verify target device belongs to current user
  const targetDevice = await DeviceKey.findOne({ user: req.user.id, deviceId: targetDeviceId });
  if (!targetDevice) throw new ApiError(404, 'Target device not found for your account');
  if (targetDevice.status === 'revoked') throw new ApiError(400, 'Cannot authorize revoked device');

  // Authorize caller device: caller must have historyAllowed = true or be owner
  const callerDeviceId = req.headers['x-device-id'];
  if (callerDeviceId) {
    const callerDevice = await DeviceKey.findOne({ user: req.user.id, deviceId: callerDeviceId });
    if (callerDevice && callerDevice.status === 'revoked') {
      throw new ApiError(403, 'Your device session is revoked');
    }
  }

  let updatedCount = 0;
  for (const item of envelopes) {
    if (!item?.messageId || !item?.envelope) continue;
    assertObjectId(item.messageId, 'message ID');
    const env = item.envelope;
    if (typeof env.ephemeralPublicKey !== 'string' || typeof env.salt !== 'string' || typeof env.keyNonce !== 'string' || typeof env.encryptedKey !== 'string') {
      continue;
    }

    const newEnvelope = {
      recipientDeviceId: targetDeviceId,
      oneTimePreKeyId: env.oneTimePreKeyId || null,
      ephemeralPublicKey: env.ephemeralPublicKey,
      salt: env.salt,
      keyNonce: env.keyNonce,
      encryptedKey: env.encryptedKey
    };

    // Update message: remove existing envelope for targetDeviceId if any, then add new one
    await Message.updateOne(
      { _id: item.messageId },
      {
        $pull: { 'encryptedPayload.recipientEnvelopes': { recipientDeviceId: targetDeviceId } }
      }
    );
    const updated = await Message.updateOne(
      { _id: item.messageId, 'encryptedPayload.version': 1 },
      {
        $push: { 'encryptedPayload.recipientEnvelopes': newEnvelope }
      }
    );
    if (updated.modifiedCount > 0) updatedCount++;
  }

  // Update target device to full history access
  targetDevice.historyAllowed = true;
  targetDevice.historyAllowedAt = null;
  targetDevice.status = 'authorized';
  await targetDevice.save();

  // Notify user's sockets
  const io = req.app.get('io');
  if (io) {
    io.to(`user:${req.user.id}`).emit('device:permission_updated', {
      deviceId: targetDeviceId,
      historyAllowed: true,
      newMessagesAllowed: targetDevice.newMessagesAllowed,
      status: 'authorized'
    });
  }

  ok(res, { targetDeviceId, updatedCount, historyAllowed: true }, 'Historical encryption keys authorized');
}

export async function getUserKeyBundles(req, res) {
  assertObjectId(req.params.userId, 'user ID');
  const other = String(req.params.userId);

  if (other !== String(req.user.id)) {
    const mutual = await Conversation.exists({ members: { $all: [req.user.id, other] } });
    if (!mutual) throw new ApiError(404, 'User or shared conversation not found');
  }

  // Filter devices: only include devices that are authorized to receive new messages and not revoked/blocked
  const devices = await DeviceKey.find({
    user: other,
    newMessagesAllowed: { $ne: false },
    status: { $nin: ['fully_blocked', 'revoked'] }
  }).select('+oneTimePreKeys');

  if (!devices.length) throw new ApiError(404, 'No active encryption keys registered for this user');

  const bundles = [];
  for (const d of devices) {
    let preKey = null;
    if (d.oneTimePreKeys?.length) {
      preKey = d.oneTimePreKeys[0];
      const pulled = await DeviceKey.findOneAndUpdate(
        { _id: d._id, 'oneTimePreKeys.keyId': preKey.keyId },
        { $pull: { oneTimePreKeys: { keyId: preKey.keyId } } },
        { new: false }
      );
      if (!pulled) preKey = null;
    }
    bundles.push({
      userId: other,
      deviceId: d.deviceId,
      identityPublicKey: d.identityPublicKey,
      signedPreKeyPublic: d.signedPreKeyPublic,
      signedPreKeySignature: d.signedPreKeySignature,
      oneTimePreKey: preKey
    });
  }
  ok(res, bundles, 'Encryption key bundles');
}

export async function replenishOneTimePreKeys(req, res) {
  const b = req.body || {};
  if (!Array.isArray(b.oneTimePreKeys) || b.oneTimePreKeys.length < 1 || b.oneTimePreKeys.length > 500) {
    throw new ApiError(400, 'Provide 1-500 one-time prekeys');
  }
  const deviceId = String(b.deviceId || '');
  const d = await DeviceKey.findOne({ user: req.user.id, deviceId });
  if (!d) throw new ApiError(404, 'Device keys not found');
  const existing = new Set(d.oneTimePreKeys.map(p => p.keyId));
  for (const p of b.oneTimePreKeys) {
    if (!p || typeof p.keyId !== 'string' || typeof p.publicKey !== 'string' || p.publicKey.length < 20 || p.publicKey.length > 4096 || existing.has(p.keyId)) {
      throw new ApiError(400, 'Invalid or duplicate one-time prekey');
    }
    existing.add(p.keyId);
  }
  d.oneTimePreKeys.push(...b.oneTimePreKeys);
  await d.save();
  ok(res, { remaining: d.oneTimePreKeys.length }, 'One-time prekeys replenished');
}
