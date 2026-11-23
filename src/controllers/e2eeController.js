import User from '../models/User.js';
import DeviceKey from '../models/DeviceKey.js';
import Conversation from '../models/Conversation.js';
import Message from '../models/Message.js';
import { ApiError } from '../utils/ApiError.js';
import { ok } from '../utils/respond.js';
import { assertObjectId } from '../utils/ids.js';
import { parseDeviceInfo } from '../utils/deviceInfo.js';
import { revokeSession } from '../services/tokenService.js';
import { randomUUID } from 'node:crypto';
import { createPublicKey, verify as verifySignature } from 'node:crypto';
import SecurityAuditEvent from '../models/SecurityAuditEvent.js';
import { conversationAccess } from '../services/accessPolicy.js';
import { getSession } from '../services/tokenService.js';

const clean = (d, includePrekeys = true) => ({
  userId: String(d.user),
  deviceId: d.deviceId,
  deviceName: d.deviceName || 'Web Browser',
  os: d.os || 'Unknown OS',
  browser: d.browser || 'Browser',
  deviceType: d.deviceType || 'browser',
  lastSeenAt: d.lastSeenAt,
  createdAt: d.createdAt,
  historyAllowed: d.historyAllowed !== false,
  newMessagesAllowed: d.newMessagesAllowed !== false,
  status: d.status || 'authorized',
  historyAllowedAt: d.historyAllowedAt || null,
  isPrimary: d.isPrimary === true,
  linkStatus: d.linkStatus || 'approved',
  linkChallenge: d.linkStatus === 'pending' ? d.linkChallenge : undefined,
  profileId: d.profileId ? String(d.profileId) : null,
  identityPublicKey: d.identityPublicKey,
  signedPreKeyPublic: d.signedPreKeyPublic,
  signedPreKeySignature: d.signedPreKeySignature,
  tabs: d.tabs || [],
  ...(includePrekeys ? { oneTimePreKeyCount: d.oneTimePreKeys?.length || 0 } : {})
});

function verifyAccountBackup(identityPublicKey, backup, signature) {
  try {
    if (typeof signature !== 'string' || signature.length < 80 || signature.length > 200) return false;
    const jwk = JSON.parse(Buffer.from(identityPublicKey, 'base64').toString('utf8'));
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    const statement = `orbit-account-backup-v1\n${backup.encryptedData}\n${backup.salt}\n${backup.iv}`;
    return verifySignature('sha256', Buffer.from(statement), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64'));
  } catch { return false; }
}

export async function registerDeviceKeys(req, res) {
  const b = req.body || {};
  if (typeof b.deviceId !== 'string' || b.deviceId.length < 1 || b.deviceId.length > 100) {
    throw new ApiError(400, 'deviceId is required (1-100 characters)');
  }
  if (b.deviceId !== req.deviceId) throw new ApiError(403, 'Device ID must match the authenticated session');
  for (const k of ['identityPublicKey', 'signedPreKeyPublic', 'signedPreKeySignature']) {
    if (typeof b[k] !== 'string' || b[k].length < 20 || b[k].length > 4096) {
      throw new ApiError(400, `${k} is invalid`);
    }
  }
  if (b.oneTimePreKeys !== undefined && (!Array.isArray(b.oneTimePreKeys) || b.oneTimePreKeys.length > 500)) {
    throw new ApiError(400, 'oneTimePreKeys must be an array with at most 500 entries');
  }
  b.oneTimePreKeys ||= [];

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
  const deviceType = parsed.deviceType;
  const ipAddress = req.ip || req.connection?.remoteAddress || '';
  const userAgent = req.headers['user-agent'] || '';
  const session = await getSession(req.sessionId, req.user.id);
  const makePrimary = session?.loginMethod === 'phone';
  const userDoc = await User.findById(req.user.id).select('privacy accountKeys');

  // Check if this device already exists
  let existingDoc = await DeviceKey.findOne({ user: req.user.id, deviceId: b.deviceId });

  let historyAllowed = true;
  let newMessagesAllowed = true;
  let status = 'authorized';
  let historyAllowedAt = null;
  let isPrimary = false;
  let linkStatus = 'approved';
  let linkChallenge = '';

  if (existingDoc) {
    // A fresh authenticated login can restore a previously revoked browser session.
    if (existingDoc.status === 'revoked') {
      historyAllowed = true;
      newMessagesAllowed = true;
      status = 'authorized';
      historyAllowedAt = null;
      isPrimary = existingDoc.isPrimary === true;
      linkStatus = 'approved';
      linkChallenge = '';
    } else {
      historyAllowed = existingDoc.historyAllowed !== false;
      newMessagesAllowed = existingDoc.newMessagesAllowed !== false;
      status = existingDoc.status || 'authorized';
      historyAllowedAt = existingDoc.historyAllowedAt;
      isPrimary = existingDoc.isPrimary === true;
      linkStatus = existingDoc.linkStatus || 'approved';
      linkChallenge = existingDoc.linkChallenge || '';
    }
    if (userDoc?.accountKeys?.identityPublicKey) {
      historyAllowed = true;
      newMessagesAllowed = true;
      status = 'authorized';
      historyAllowedAt = null;
      linkStatus = 'approved';
      linkChallenge = '';
    }
  } else {
    // New device registration: check if this is user's first device
    const priorDevicesCount = await DeviceKey.countDocuments({
      user: req.user.id,
      deviceId: { $ne: b.deviceId },
      status: { $ne: 'revoked' }
    });
    const primaryExists = await DeviceKey.exists({ user: req.user.id, isPrimary: true, status: { $ne: 'revoked' } });
    if (priorDevicesCount > 0 && !primaryExists) {
      const oldest = await DeviceKey.findOne({ user: req.user.id, status: { $ne: 'revoked' } }).sort({ createdAt: 1 });
      if (oldest) {
        oldest.isPrimary = true;
        oldest.linkStatus = 'approved';
        await oldest.save();
        if (oldest.deviceId === b.deviceId) isPrimary = true;
      }
    }

    const isStrictPrivacy = userDoc?.privacy?.strictDevicePrivacy === true && !userDoc?.accountKeys?.identityPublicKey;

    if (priorDevicesCount > 0 && isStrictPrivacy) {
      historyAllowed = false;
      newMessagesAllowed = false;
      status = 'authorized';
      historyAllowedAt = new Date();
      linkStatus = 'pending';
      linkChallenge = randomUUID();
    } else {
      historyAllowed = true;
      newMessagesAllowed = true;
      status = 'authorized';
      linkStatus = 'approved';
      linkChallenge = '';
      if (!primaryExists || priorDevicesCount === 0) {
        isPrimary = true;
      }
    }
  }

  const anotherPrimary = await DeviceKey.exists({ user: req.user.id, isPrimary: true, deviceId: { $ne: b.deviceId }, status: { $ne: 'revoked' } });
  if (makePrimary) {
    if (anotherPrimary) await DeviceKey.updateMany({ user: req.user.id, deviceId: { $ne: b.deviceId } }, { $set: { isPrimary: false } });
    isPrimary = true;
    linkStatus = 'approved';
    linkChallenge = '';
    status = 'authorized';
    historyAllowed = true;
    newMessagesAllowed = true;
    historyAllowedAt = null;
  }

  const doc = await DeviceKey.findOneAndUpdate(
    { user: req.user.id, deviceId: b.deviceId },
    {
      $set: {
        identityPublicKey: b.identityPublicKey,
        signedPreKeyPublic: b.signedPreKeyPublic,
        signedPreKeySignature: b.signedPreKeySignature,
        ...(userDoc?.accountKeys?.identityPublicKey
          ? { oneTimePreKeys: [] }
          : b.oneTimePreKeys.length || !existingDoc ? { oneTimePreKeys: b.oneTimePreKeys } : {}),
        lastSeenAt: new Date(),
        deviceName,
        os,
        browser,
        deviceType,
        ipAddress,
        userAgent,
        historyAllowed,
        newMessagesAllowed,
        status,
        historyAllowedAt,
        isPrimary,
        linkStatus,
        linkChallenge,
        sessionId: req.sessionId || ''
      }
    },
    { upsert: true, new: true, runValidators: true }
  );
  await SecurityAuditEvent.create({
    user: req.user.id,
    actorDeviceId: req.deviceId,
    action: linkStatus === 'pending' ? 'device_link_requested' : 'device_enrolled',
    targetType: 'device',
    targetId: doc.deviceId
  });

  ok(res, clean(doc), 'Public device keys registered');
}

export async function authorizeDeviceLink(req, res) {
  if (!req.device?.isPrimary || req.device.linkStatus !== 'approved') {
    throw new ApiError(403, 'Only the approved primary device can authorize a linked device');
  }
  const target = await DeviceKey.findOne({
    user: req.user.id,
    deviceId: String(req.params.deviceId || ''),
    status: { $ne: 'revoked' },
    linkStatus: 'pending'
  });
  if (!target) throw new ApiError(404, 'Pending device link not found');
  const signature = req.body?.signature;
  if (typeof signature !== 'string' || signature.length < 80 || signature.length > 200) {
    throw new ApiError(400, 'Device authorization signature is invalid');
  }
  const message = [
    'orbit-device-link-v1',
    String(req.user.id),
    target.deviceId,
    target.identityPublicKey,
    target.linkChallenge
  ].join('\n');
  let valid = false;
  try {
    const jwk = JSON.parse(Buffer.from(req.device.identityPublicKey, 'base64').toString('utf8'));
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    valid = verifySignature('sha256', Buffer.from(message), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64'));
  } catch {
    valid = false;
  }
  if (!valid) throw new ApiError(403, 'Primary-device signature could not be verified');
  target.linkStatus = 'approved';
  target.linkChallenge = '';
  target.newMessagesAllowed = true;
  target.status = 'authorized';
  await target.save();
  await SecurityAuditEvent.create({
    user: req.user.id,
    actorDeviceId: req.deviceId,
    action: 'device_link_approved',
    targetType: 'device',
    targetId: target.deviceId
  });
  ok(res, clean(target), 'Device link approved');
}

export async function renameDevice(req, res) {
  const device = await DeviceKey.findOne({ user: req.user.id, deviceId: String(req.params.deviceId || ''), status: { $ne: 'revoked' } });
  if (!device) throw new ApiError(404, 'Device not found');
  if (device.deviceId !== req.deviceId && !req.device?.isPrimary) {
    throw new ApiError(403, 'Only the primary device can rename another device');
  }
  const name = String(req.body?.deviceName || '').trim();
  if (!name || name.length > 80) throw new ApiError(400, 'Device name must be 1-80 characters');
  device.deviceName = name;
  await device.save();
  await SecurityAuditEvent.create({ user: req.user.id, actorDeviceId: req.deviceId, action: 'device_renamed', targetType: 'device', targetId: device.deviceId });
  ok(res, clean(device), 'Device renamed');
}

export async function listMyDevices(req, res) {
  const ds = await DeviceKey.find({ user: req.user.id })
    .select('deviceId deviceName os browser deviceType sessionId lastSeenAt createdAt isPrimary linkStatus historyAllowed newMessagesAllowed status historyAllowedAt identityPublicKey signedPreKeyPublic signedPreKeySignature oneTimePreKeys.length tabs')
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
  if (!req.device?.isPrimary) throw new ApiError(403, 'Primary-device approval is required');
  const deviceId = String(req.params.deviceId || '');
  const doc = await DeviceKey.findOne({ user: req.user.id, deviceId });
  if (!doc) throw new ApiError(404, 'Device not found');
  if (doc.isPrimary && (req.body.policy === 'block' || req.body.newMessagesAllowed === false || req.body.historyAllowed === false)) {
    throw new ApiError(400, 'The primary device cannot revoke its own access');
  }

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
  await SecurityAuditEvent.create({ user: req.user.id, actorDeviceId: req.deviceId, action: 'device_permissions_updated', targetType: 'device', targetId: doc.deviceId });

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
  if (!req.device?.isPrimary) throw new ApiError(403, 'Primary-device approval is required');
  const deviceId = String(req.params.deviceId || '');
  const doc = await DeviceKey.findOne({ user: req.user.id, deviceId });
  if (!doc) throw new ApiError(404, 'Device not found');
  if (doc.isPrimary) throw new ApiError(400, 'The primary device cannot revoke itself');

  doc.status = 'revoked';
  doc.historyAllowed = false;
  doc.newMessagesAllowed = false;
  await doc.save();
  await SecurityAuditEvent.create({ user: req.user.id, actorDeviceId: req.deviceId, action: 'device_revoked', targetType: 'device', targetId: doc.deviceId });

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
  if (!req.device?.isPrimary) throw new ApiError(403, 'Primary-device approval is required');
  const deviceId = String(req.params.deviceId || '');
  const doc = await DeviceKey.findOne({ user: req.user.id, deviceId });
  if (!doc) throw new ApiError(404, 'Device not found');
  if (doc.isPrimary) throw new ApiError(400, 'The primary device cannot be deleted; use the supported replacement workflow');

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
  if (deviceId !== req.deviceId) throw new ApiError(403, 'Tabs can only be managed by their enrolled device');

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
  if (deviceId !== req.deviceId) throw new ApiError(403, 'Tabs can only be managed by their enrolled device');
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
  const complete = b.complete === true;

  if (!targetDeviceId) throw new ApiError(400, 'targetDeviceId is required');
  if (!envelopes.length && !complete) throw new ApiError(400, 'No envelopes provided');

  // Verify target device belongs to current user
  const targetDevice = await DeviceKey.findOne({ user: req.user.id, deviceId: targetDeviceId });
  if (!targetDevice) throw new ApiError(404, 'Target device not found for your account');
  if (targetDevice.status === 'revoked' || targetDevice.linkStatus !== 'approved') throw new ApiError(400, 'Cannot authorize a pending or revoked device');

  if (!req.device?.isPrimary || req.device.historyAllowed === false) {
    throw new ApiError(403, 'Only the authorized primary device can approve message history');
  }

  let updatedCount = 0;
  for (const item of envelopes) {
    if (!item?.messageId || !item?.envelope) continue;
    assertObjectId(item.messageId, 'message ID');
    const envelope = item.envelope;
    if (typeof envelope.ephemeralPublicKey !== 'string' || typeof envelope.salt !== 'string' || typeof envelope.keyNonce !== 'string' || typeof envelope.encryptedKey !== 'string') {
      continue;
    }
    const message = await Message.findOne({ _id: item.messageId, deletedForEveryone: false }).select('conversation');
    const conversation = message && await Conversation.findOne({ _id: message.conversation, members: req.user.id });
    if (!message || !conversation) {
      throw new ApiError(404, 'Message not found');
    }
    const historyAccess = await conversationAccess(
      conversation,
      req.user.id,
      { ...targetDevice.toObject(), historyAllowed: true },
      'history'
    );
    if (!historyAccess.allowed) throw new ApiError(403, 'The target device is not permitted to receive keys for this conversation');

    const newEnvelope = {
      recipientDeviceId: targetDeviceId,
      oneTimePreKeyId: envelope.oneTimePreKeyId || null,
      ephemeralPublicKey: envelope.ephemeralPublicKey,
      salt: envelope.salt,
      keyNonce: envelope.keyNonce,
      encryptedKey: envelope.encryptedKey
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

  if (complete) {
    targetDevice.historyAllowed = true;
    targetDevice.historyAllowedAt = null;
    targetDevice.status = 'authorized';
    await targetDevice.save();
  }

  // Notify user's sockets
  const io = req.app.get('io');
  if (io) {
    io.to(`user:${req.user.id}`).emit('device:permission_updated', {
      deviceId: targetDeviceId,
      historyAllowed: targetDevice.historyAllowed,
      newMessagesAllowed: targetDevice.newMessagesAllowed,
      status: 'authorized'
    });
  }

  ok(res, { targetDeviceId, updatedCount, historyAllowed: targetDevice.historyAllowed }, complete ? 'Historical encryption keys authorized' : 'Historical encryption keys transferred');
}

export async function getUserKeyBundles(req, res) {
  assertObjectId(req.params.userId, 'user ID');
  const other = String(req.params.userId);

  const conversationId = String(req.query.conversationId || '');
  assertObjectId(conversationId, 'conversation ID');
  const conversation = await Conversation.findOne({ _id: conversationId, members: { $all: [req.user.id, other] } });
  if (!conversation) throw new ApiError(404, 'User or shared conversation not found');
  const recipient = await User.findById(other).select('accountKeys status');
  if (!recipient || recipient.status !== 'active' || !recipient.accountKeys?.identityPublicKey) {
    return ok(res, [], 'This account has not finished secure setup');
  }
  ok(res, [{
    userId: other,
    deviceId: other,
    identityPublicKey: recipient.accountKeys.identityPublicKey,
    signedPreKeyPublic: recipient.accountKeys.signedPreKeyPublic,
    signedPreKeySignature: recipient.accountKeys.signedPreKeySignature,
    oneTimePreKey: null
  }], 'Account encryption key retrieved');
}

export async function replenishOneTimePreKeys(req, res) {
  const b = req.body || {};
  if (!Array.isArray(b.oneTimePreKeys) || b.oneTimePreKeys.length < 1 || b.oneTimePreKeys.length > 500) {
    throw new ApiError(400, 'Provide 1-500 one-time prekeys');
  }
  const deviceId = String(b.deviceId || '');
  if (deviceId !== req.deviceId) throw new ApiError(403, 'Prekeys can only be replenished by their enrolled device');
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


export async function getKeyBackup(req, res) {
  const user = await User.findById(req.user.id).select('keyBackup encryptionMode');
  ok(res, {
    keyBackup: user?.keyBackup || null,
    encryptionMode: user?.encryptionMode || 'all_devices'
  }, 'Key backup retrieved');
}

export async function getAccountKeys(req, res) {
  const user = await User.findById(req.user.id).select('accountKeys keyBackup');
  ok(res, { accountKeys: user?.accountKeys || null, keyBackup: user?.keyBackup || null }, 'Account encryption keys retrieved');
}

export async function createAccountKeys(req, res) {
  const { identityPublicKey, signedPreKeyPublic, signedPreKeySignature, encryptedData, salt, iv, backupSignature } = req.body || {};
  for (const [name, value] of Object.entries({ identityPublicKey, signedPreKeyPublic, signedPreKeySignature, encryptedData, salt, iv })) {
    const minimum = name === 'iv' ? 16 : name === 'salt' ? 22 : 20;
    const maximum = name === 'encryptedData' ? 1500000 : 4096;
    if (typeof value !== 'string' || value.length < minimum || value.length > maximum) throw new ApiError(400, `${name} is invalid`);
  }
  let signatureValid = false;
  try {
    const jwk = JSON.parse(Buffer.from(identityPublicKey, 'base64').toString('utf8'));
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    signatureValid = verifySignature('sha256', Buffer.from(signedPreKeyPublic), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(signedPreKeySignature, 'base64'));
  } catch { signatureValid = false; }
  if (!signatureValid) throw new ApiError(400, 'Account signed prekey signature is invalid');
  if (!verifyAccountBackup(identityPublicKey, { encryptedData, salt, iv }, backupSignature)) {
    throw new ApiError(400, 'Account backup signature is invalid');
  }
  const user = await User.findOneAndUpdate(
    { _id: req.user.id, $or: [{ 'accountKeys.identityPublicKey': null }, { 'accountKeys.identityPublicKey': { $exists: false } }] },
    { $set: {
      'accountKeys.identityPublicKey': identityPublicKey,
      'accountKeys.signedPreKeyPublic': signedPreKeyPublic,
      'accountKeys.signedPreKeySignature': signedPreKeySignature,
      'privacy.strictDevicePrivacy': false,
      'keyBackup.encryptedData': encryptedData,
      'keyBackup.salt': salt,
      'keyBackup.iv': iv,
      'keyBackup.updatedAt': new Date()
    } },
    { new: true }
  );
  if (!user) throw new ApiError(409, 'Account encryption keys are already set up');
  await SecurityAuditEvent.create({ user: req.user.id, action: 'account_keys_created', targetType: 'account', targetId: req.user.id });
  ok(res, { accountKeys: user.accountKeys, keyBackup: user.keyBackup }, 'Account encryption keys created');
}

export async function updateAccountKeyBackup(req, res) {
  const { encryptedData, salt, iv, backupSignature } = req.body || {};
  for (const [name, value] of Object.entries({ encryptedData, salt, iv })) {
    const minimum = name === 'iv' ? 16 : name === 'salt' ? 22 : 20;
    const maximum = name === 'encryptedData' ? 1500000 : 4096;
    if (typeof value !== 'string' || value.length < minimum || value.length > maximum) throw new ApiError(400, `${name} is invalid`);
  }
  const current = await User.findById(req.user.id).select('accountKeys');
  if (!current?.accountKeys?.identityPublicKey) throw new ApiError(409, 'Set up account encryption before saving its backup');
  if (!verifyAccountBackup(current.accountKeys.identityPublicKey, { encryptedData, salt, iv }, backupSignature)) {
    throw new ApiError(403, 'Account backup signature could not be verified');
  }
  const user = await User.findOneAndUpdate(
    { _id: req.user.id, 'accountKeys.identityPublicKey': { $type: 'string' } },
    { $set: { 'keyBackup.encryptedData': encryptedData, 'keyBackup.salt': salt, 'keyBackup.iv': iv, 'keyBackup.updatedAt': new Date() } },
    { new: true }
  ).select('accountKeys keyBackup');
  if (!user) throw new ApiError(409, 'Set up account encryption before saving its backup');
  await SecurityAuditEvent.create({ user: req.user.id, action: 'account_key_backup_updated', targetType: 'account', targetId: req.user.id });
  ok(res, { accountKeys: user.accountKeys, keyBackup: user.keyBackup }, 'Account key backup updated');
}

export async function saveKeyBackup(req, res) {
  const { encryptedData, salt, iv, encryptionMode, backupSignature } = req.body || {};
  if (!encryptedData || !salt || !iv) {
    throw new ApiError(400, 'encryptedData, salt, and iv are required for key backup');
  }
  const owner = await User.findById(req.user.id).select('accountKeys');
  if (!owner?.accountKeys?.identityPublicKey || !verifyAccountBackup(owner.accountKeys.identityPublicKey, { encryptedData, salt, iv }, backupSignature)) {
    throw new ApiError(403, 'Account backup signature could not be verified');
  }
  const update = {
    'keyBackup.encryptedData': encryptedData,
    'keyBackup.salt': salt,
    'keyBackup.iv': iv,
    'keyBackup.updatedAt': new Date()
  };
  if (encryptionMode && ['all_devices', 'mobile_only'].includes(encryptionMode)) {
    update.encryptionMode = encryptionMode;
  }
  const user = await User.findByIdAndUpdate(req.user.id, { $set: update }, { new: true });
  await SecurityAuditEvent.create({
    user: req.user.id,
    actorDeviceId: req.deviceId,
    action: 'key_backup_saved',
    targetType: 'account',
    targetId: req.user.id
  });
  ok(res, { hasKeyBackup: true, encryptionMode: user?.encryptionMode || 'all_devices' }, 'Key backup saved successfully');
}

export async function updateEncryptionMode(req, res) {
  const { mode } = req.body || {};
  if (!['all_devices', 'mobile_only'].includes(mode)) {
    throw new ApiError(400, 'Mode must be all_devices or mobile_only');
  }
  const user = await User.findByIdAndUpdate(req.user.id, { $set: { encryptionMode: mode } }, { new: true });
  await SecurityAuditEvent.create({
    user: req.user.id,
    actorDeviceId: req.deviceId,
    action: 'encryption_mode_updated',
    targetType: 'account',
    targetId: req.user.id,
    details: { mode }
  });
  ok(res, { encryptionMode: user?.encryptionMode || 'all_devices' }, 'Encryption mode updated');
}
