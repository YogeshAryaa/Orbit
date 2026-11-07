import Conversation from '../models/Conversation.js';
import DeviceKey from '../models/DeviceKey.js';
import DeviceProfile from '../models/DeviceProfile.js';
import SecurityAuditEvent from '../models/SecurityAuditEvent.js';
import { ApiError } from '../utils/ApiError.js';
import { ok } from '../utils/respond.js';
import { assertObjectId } from '../utils/ids.js';
import { conversationAccess } from '../services/accessPolicy.js';

async function audit(req, action, targetType, targetId, details = {}) {
  await SecurityAuditEvent.create({
    user: req.user.id,
    actorDeviceId: req.deviceId,
    action,
    targetType,
    targetId: String(targetId || ''),
    details
  });
}

export async function getConversationAccess(req, res) {
  assertObjectId(req.params.id, 'conversation ID');
  const conversation = await Conversation.findOne({ _id: req.params.id, members: req.user.id });
  if (!conversation) throw new ApiError(404, 'Conversation not found');
  const policy = conversation.memberAccessPolicies.find(item => String(item.user) === String(req.user.id));
  const access = await conversationAccess(conversation, req.user.id, req.device, 'new');
  ok(res, {
    mode: policy?.mode || 'all_authorized',
    selectedDeviceIds: policy?.selectedDeviceIds || [],
    groupAccessMode: conversation.type === 'group' ? conversation.groupAccessMode : null,
    effectiveAccess: access.allowed ? 'full_decryption' : 'header_only'
  });
}

export async function updateConversationAccess(req, res) {
  assertObjectId(req.params.id, 'conversation ID');
  const conversation = await Conversation.findOne({ _id: req.params.id, members: req.user.id });
  if (!conversation) throw new ApiError(404, 'Conversation not found');
  const { mode, selectedDeviceIds = [] } = req.body;
  if (!['all_authorized', 'mobile_only', 'selected_devices', 'master_authorization'].includes(mode)) {
    throw new ApiError(400, 'Invalid conversation access mode');
  }
  if (!Array.isArray(selectedDeviceIds) || selectedDeviceIds.length > 100 ||
      selectedDeviceIds.some(id => typeof id !== 'string' || id.length > 100)) {
    throw new ApiError(400, 'Invalid selected device list');
  }
  if (mode === 'selected_devices') {
    const owned = await DeviceKey.find({ user: req.user.id, deviceId: { $in: selectedDeviceIds }, status: 'authorized', linkStatus: 'approved' }).select('deviceId');
    if (owned.length !== new Set(selectedDeviceIds).size) throw new ApiError(400, 'Selected devices must be approved devices on your account');
  }
  const policy = conversation.memberAccessPolicies.find(item => String(item.user) === String(req.user.id));
  if (policy) {
    policy.mode = mode;
    policy.selectedDeviceIds = mode === 'selected_devices' ? [...new Set(selectedDeviceIds)] : [];
  } else {
    conversation.memberAccessPolicies.push({
      user: req.user.id,
      mode,
      selectedDeviceIds: mode === 'selected_devices' ? [...new Set(selectedDeviceIds)] : []
    });
  }
  await conversation.save();
  await audit(req, 'conversation_access_updated', 'conversation', conversation.id, { mode });
  const access = await conversationAccess(conversation, req.user.id, req.device, 'new');
  ok(res, {
    mode,
    selectedDeviceIds: mode === 'selected_devices' ? [...new Set(selectedDeviceIds)] : [],
    effectiveAccess: access.allowed ? 'full_decryption' : 'header_only'
  }, 'Conversation access updated');
}

export async function updateGroupAccess(req, res) {
  assertObjectId(req.params.id, 'conversation ID');
  const conversation = await Conversation.findOne({
    _id: req.params.id,
    type: 'group',
    members: req.user.id,
    admins: req.user.id
  });
  if (!conversation) throw new ApiError(403, 'Group administrator access required');
  const { mode } = req.body;
  if (!['full_decryption', 'header_only'].includes(mode)) throw new ApiError(400, 'Invalid group access mode');
  conversation.groupAccessMode = mode;
  await conversation.save();
  await audit(req, 'group_access_updated', 'conversation', conversation.id, { mode });
  ok(res, { conversationId: conversation.id, mode }, 'Group access mode updated');
}

export async function authorizeConversationDevice(req, res) {
  assertObjectId(req.params.id, 'conversation ID');
  const conversation = await Conversation.findOne({ _id: req.params.id, members: req.user.id });
  if (!conversation) throw new ApiError(404, 'Conversation not found');
  if (!req.device?.isPrimary || req.device.linkStatus !== 'approved') {
    throw new ApiError(403, 'Primary-device authorization is required');
  }
  const targetDeviceId = String(req.body.deviceId || '');
  const target = await DeviceKey.findOne({ user: req.user.id, deviceId: targetDeviceId, status: 'authorized', linkStatus: 'approved' });
  if (!target) throw new ApiError(404, 'Approved target device not found');
  const minutes = req.body.minutes === undefined ? 15 : Number(req.body.minutes);
  if (!Number.isInteger(minutes) || minutes < 1 || minutes > 30) throw new ApiError(400, 'Authorization must last 1-30 minutes');
  target.masterAuthorizations = (target.masterAuthorizations || []).filter(entry => String(entry.conversation) !== conversation.id);
  target.masterAuthorizations.push({ conversation: conversation._id, expiresAt: new Date(Date.now() + minutes * 60_000) });
  await target.save();
  await audit(req, 'master_authorized_device', 'device', targetDeviceId, { conversationId: conversation.id, minutes });
  ok(res, { deviceId: targetDeviceId, conversationId: conversation.id, expiresAt: target.masterAuthorizations.at(-1).expiresAt }, 'Device authorized by primary device');
}

export async function listProfiles(req, res) {
  const profiles = await DeviceProfile.find({ user: req.user.id }).sort({ name: 1 }).lean();
  ok(res, profiles);
}

export async function createProfile(req, res) {
  const { name, allowedConversations = [], allowedGroups = [] } = req.body;
  if (typeof name !== 'string' || !name.trim() || name.length > 60) throw new ApiError(400, 'Profile name must be 1-60 characters');
  if (!Array.isArray(allowedConversations) || !Array.isArray(allowedGroups) || allowedConversations.length + allowedGroups.length > 200) {
    throw new ApiError(400, 'Profile conversation list is invalid');
  }
  const ids = [...allowedConversations, ...allowedGroups];
  ids.forEach(id => assertObjectId(id, 'conversation ID'));
  const found = await Conversation.find({ _id: { $in: ids }, members: req.user.id }).select('_id type');
  if (found.length !== new Set(ids).size) throw new ApiError(400, 'Profiles may include only conversations you belong to');
  const conversationSet = new Set(allowedConversations);
  if (allowedGroups.some(id => conversationSet.has(id)) || found.some(row =>
    allowedGroups.includes(String(row._id)) ? row.type !== 'group' : row.type === 'group'
  )) {
    throw new ApiError(400, 'Profile entries must match the selected conversation type');
  }
  const profile = await DeviceProfile.create({
    user: req.user.id,
    name: name.trim(),
    allowedConversations: [...new Set(allowedConversations)],
    allowedGroups: [...new Set(allowedGroups)]
  });
  await audit(req, 'device_profile_created', 'profile', profile.id, { name: profile.name });
  ok(res, profile, 'Device profile created', 201);
}

export async function updateProfile(req, res) {
  assertObjectId(req.params.profileId, 'profile ID');
  const profile = await DeviceProfile.findOne({ _id: req.params.profileId, user: req.user.id });
  if (!profile) throw new ApiError(404, 'Device profile not found');
  const { name, allowedConversations = profile.allowedConversations.map(String), allowedGroups = profile.allowedGroups.map(String) } = req.body;
  if (name !== undefined && (typeof name !== 'string' || !name.trim() || name.length > 60)) throw new ApiError(400, 'Profile name must be 1-60 characters');
  if (!Array.isArray(allowedConversations) || !Array.isArray(allowedGroups) || allowedConversations.length + allowedGroups.length > 200) throw new ApiError(400, 'Profile conversation list is invalid');
  const ids = [...allowedConversations, ...allowedGroups];
  ids.forEach(id => assertObjectId(id, 'conversation ID'));
  const found = await Conversation.find({ _id: { $in: ids }, members: req.user.id }).select('_id type');
  const conversationSet = new Set(allowedConversations);
  if (found.length !== new Set(ids).size || allowedGroups.some(id => conversationSet.has(id)) || found.some(row =>
    allowedGroups.includes(String(row._id)) ? row.type !== 'group' : row.type === 'group'
  )) {
    throw new ApiError(400, 'Profile entries must match conversations you belong to and their type');
  }
  profile.name = name === undefined ? profile.name : name.trim();
  profile.allowedConversations = [...new Set(allowedConversations)];
  profile.allowedGroups = [...new Set(allowedGroups)];
  await profile.save();
  await audit(req, 'device_profile_updated', 'profile', profile.id, { name: profile.name });
  ok(res, profile, 'Device profile updated');
}

export async function deleteProfile(req, res) {
  assertObjectId(req.params.profileId, 'profile ID');
  const profile = await DeviceProfile.findOne({ _id: req.params.profileId, user: req.user.id });
  if (!profile) throw new ApiError(404, 'Device profile not found');
  await DeviceKey.updateMany({ user: req.user.id, profileId: profile._id }, { $set: { profileId: null } });
  await profile.deleteOne();
  await audit(req, 'device_profile_deleted', 'profile', profile.id);
  ok(res, null, 'Device profile deleted');
}

export async function assignProfile(req, res) {
  if (!req.device?.isPrimary) throw new ApiError(403, 'Primary-device approval is required');
  const deviceId = String(req.params.deviceId || '');
  const profileId = req.body.profileId ? String(req.body.profileId) : null;
  const device = await DeviceKey.findOne({ user: req.user.id, deviceId, status: { $ne: 'revoked' } });
  if (!device) throw new ApiError(404, 'Device not found');
  if (profileId) {
    assertObjectId(profileId, 'profile ID');
    if (!await DeviceProfile.exists({ _id: profileId, user: req.user.id })) throw new ApiError(404, 'Device profile not found');
  }
  device.profileId = profileId;
  await device.save();
  await audit(req, 'device_profile_assigned', 'device', deviceId, { profileId });
  ok(res, { deviceId, profileId }, 'Device profile assigned');
}

export async function listSecurityActivity(req, res) {
  const limit = Math.min(Number(req.query.limit || 50), 100);
  const events = await SecurityAuditEvent.find({ user: req.user.id }).sort({ createdAt: -1 }).limit(limit).lean();
  ok(res, events);
}
