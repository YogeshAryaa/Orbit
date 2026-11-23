import Status from '../models/Status.js';
import User from '../models/User.js';
import { ApiError } from '../utils/ApiError.js';
import { ok } from '../utils/respond.js';
import { assertObjectId } from '../utils/ids.js';

export async function createStatus(req, res) {
  const { text, backgroundColor, fontStyle } = req.validated.body;
  const activeCount = await Status.countDocuments({
    user: req.user.id,
    expiresAt: { $gt: new Date() }
  });
  if (activeCount >= 5) {
    throw new ApiError(400, 'Maximum 5 active statuses allowed');
  }

  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  const status = await Status.create({
    user: req.user.id,
    text,
    ...(backgroundColor ? { backgroundColor } : {}),
    ...(fontStyle ? { fontStyle } : {}),
    expiresAt
  });

  const populated = await status.populate('user', 'publicId username displayName avatarUrl');
  ok(res, populated, 'Status created', 201);
}

export async function getMyStatuses(req, res) {
  const statuses = await Status.find({
    user: req.user.id,
    expiresAt: { $gt: new Date() }
  })
    .sort({ createdAt: -1 })
    .populate('user', 'publicId username displayName avatarUrl')
    .populate('viewedBy', 'publicId username displayName avatarUrl');
  ok(res, statuses, 'My statuses');
}

export async function getAllStatuses(req, res) {
  const currentUser = await User.findById(req.user.id).select('blockedUsers');
  const myBlocked = currentUser?.blockedUsers || req.user.blockedUsers || [];
  const blockingUsers = await User.find({ blockedUsers: req.user.id }).select('_id');
  const excludedUserIds = [
    req.user.id,
    ...myBlocked,
    ...blockingUsers.map(u => u._id)
  ];

  const statuses = await Status.find({
    user: { $nin: excludedUserIds },
    expiresAt: { $gt: new Date() }
  })
    .sort({ createdAt: -1 })
    .populate('user', 'publicId username displayName avatarUrl');

  const groupsMap = new Map();
  for (const status of statuses) {
    if (!status.user) continue;
    const userId = String(status.user._id || status.user);
    if (!groupsMap.has(userId)) {
      groupsMap.set(userId, {
        user: status.user,
        statuses: []
      });
    }
    groupsMap.get(userId).statuses.push(status);
  }

  const result = Array.from(groupsMap.values());
  ok(res, result, 'Statuses');
}

export async function viewStatus(req, res) {
  assertObjectId(req.params.id, 'status ID');
  const currentUser = await User.findById(req.user.id).select('blockedUsers');
  const blockedUsers = currentUser?.blockedUsers || [];
  const status = await Status.findOne({
    _id: req.params.id,
    expiresAt: { $gt: new Date() },
    user: { $nin: [req.user.id, ...blockedUsers] }
  });
  if (!status) throw new ApiError(404, 'Status not found');
  if (await User.exists({ _id: status.user, blockedUsers: req.user.id })) throw new ApiError(404, 'Status not found');

  const updated = await Status.findByIdAndUpdate(
    req.params.id,
    { $addToSet: { viewedBy: req.user.id } },
    { new: true }
  ).populate('user', 'publicId username displayName avatarUrl');

  ok(res, updated, 'Status viewed');
}

export async function deleteStatus(req, res) {
  assertObjectId(req.params.id, 'status ID');
  const status = await Status.findById(req.params.id);
  if (!status) throw new ApiError(404, 'Status not found');
  if (String(status.user) !== String(req.user.id)) {
    throw new ApiError(403, 'You can only delete your own status');
  }
  await Status.deleteOne({ _id: status._id });
  ok(res, null, 'Status deleted');
}
