import DeviceProfile from '../models/DeviceProfile.js';
import DeviceKey from '../models/DeviceKey.js';
import User from '../models/User.js';
import mongoose from 'mongoose';

export async function conversationAccess(conversation, userId, device, purpose = 'history') {
  const user = mongoose.isValidObjectId(userId) ? await User.findById(userId).select('encryptionMode privacy accountKeys') : null;
  if (user?.accountKeys?.identityPublicKey) return { allowed: true, mode: 'account_keys' };
  const isStrictPrivacy = user?.privacy?.strictDevicePrivacy === true;

  if (!isStrictPrivacy) {
    // When strict privacy is OFF, allow all authenticated devices and tabs freely
    return { allowed: true, mode: 'open' };
  }

  if (!device || device.status !== 'authorized' || device.linkStatus !== 'approved') {
    return { allowed: false, mode: 'header_only' };
  }
  if (purpose === 'history' && device.historyAllowed === false) return { allowed: false, mode: 'header_only' };
  if (purpose === 'new' && device.newMessagesAllowed === false) return { allowed: false, mode: 'header_only' };
  if (conversation?.type === 'group' && conversation?.groupAccessMode === 'header_only') {
    return { allowed: false, mode: 'header_only' };
  }

  const policy = conversation?.memberAccessPolicies?.find(item => String(item.user) === String(userId));
  if (policy?.mode === 'selected_devices' && !policy.selectedDeviceIds?.includes(device.deviceId)) {
    return { allowed: false, mode: 'selected_devices' };
  }
  if (policy?.mode === 'master_authorization' && !device.isPrimary &&
      !(device.masterAuthorizations || []).some(entry =>
        String(entry.conversation) === String(conversation._id) && new Date(entry.expiresAt).getTime() > Date.now()
      )) {
    return { allowed: false, mode: 'master_authorization' };
  }
  if (policy?.mode === 'mobile_only' && device.deviceType !== 'mobile') {
    return { allowed: false, mode: 'mobile_only' };
  }

  // Mobile-wise encryption/decryption policy (account-level, mobile-wise, NOT chat-wise)
  const encryptionMode = user?.encryptionMode || 'all_devices';

  if (encryptionMode === 'mobile_only') {
    const isMobile = device.deviceType === 'mobile' || (device.isPrimary && device.deviceType === 'mobile');
    if (!isMobile) {
      return { allowed: false, mode: 'mobile_only' };
    }
  }

  return { allowed: true, mode: encryptionMode };
}

export function hideMessageContent(message) {
  const result = typeof message.toObject === 'function' ? message.toObject() : { ...message };
  delete result.text;
  result.encryptedPayload = null;
  result.attachments = [];
  result.replyTo = null;
  result.forwardedFrom = null;
  result.accessRestricted = true;
  return result;
}

export async function emitToAuthorizedConversation(io, conversation, event, payload) {
  const sockets = await io.in(String(conversation._id)).fetchSockets();
  for (const socket of sockets) {
    if (!socket.deviceId || !socket.sessionId) continue;
    const device = await DeviceKey.findOne({
      user: socket.userId,
      deviceId: socket.deviceId,
      sessionId: socket.sessionId,
      status: 'authorized',
    });
    if (!device || !(await conversationAccess(conversation, socket.userId, device, 'new')).allowed) continue;
    socket.emit(event, payload);
  }
}

export async function emitToAuthorizedUser(io, userId, conversation, event, payload) {
  const sockets = await io.in(`user:${userId}`).fetchSockets();
  for (const socket of sockets) {
    if (!socket.deviceId || !socket.sessionId) continue;
    const device = await DeviceKey.findOne({
      user: userId,
      deviceId: socket.deviceId,
      sessionId: socket.sessionId,
      status: 'authorized',
    });
    if (!device || !(await conversationAccess(conversation, userId, device, 'new')).allowed) continue;
    socket.emit(event, payload);
  }
}
