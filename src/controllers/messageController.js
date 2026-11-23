import Conversation from '../models/Conversation.js';
import Message from '../models/Message.js';
import User from '../models/User.js';
import { ApiError } from '../utils/ApiError.js';
import { ok } from '../utils/respond.js';
import { assertObjectId } from '../utils/ids.js';
import { notifyUser } from '../services/pushService.js';
import { env } from '../config/env.js';
import { conversationAccess, emitToAuthorizedConversation } from '../services/accessPolicy.js';

async function accessibleMessage(id, userId, device) {
  assertObjectId(id, 'message ID');
  const m = await Message.findById(id);
  if (!m) throw new ApiError(404, 'Message not found');
  const c = await Conversation.findOne({ _id: m.conversation, members: userId });
  if (!c) throw new ApiError(404, 'Message not found');
  if (!(await conversationAccess(c, userId, device, 'new')).allowed) {
    throw new ApiError(403, 'This device is not authorized to access message content');
  }
  return { m, c };
}

export async function sendMessage(req, res) {
  const input = req.validated.body;
  const c = await Conversation.findOne({ _id: input.conversationId, members: req.user.id });
  if (!c) throw new ApiError(404, 'Conversation not found');

  if (!(await conversationAccess(c, req.user.id, req.device, 'new')).allowed) {
    throw new ApiError(403, 'This device is not authorized to send messages in this conversation');
  }

  const recipientUsers = await User.find({ _id: { $in: c.members }, blockedUsers: req.user.id }).select('_id');
  if (recipientUsers.length) throw new ApiError(403, 'Messaging is not allowed due to block settings');

  let replyTo = null, forwardedFrom = null;
  if (input.replyTo) {
    const r = await Message.findOne({ _id: input.replyTo, conversation: c._id });
    if (!r) throw new ApiError(400, 'Reply target is not in this conversation');
    replyTo = r._id;
  }
  if (input.forwardedFrom) {
    const f = await Message.findById(input.forwardedFrom);
    if (!f || !await Conversation.exists({ _id: f.conversation, members: req.user.id })) {
      throw new ApiError(404, 'Forward source not found');
    }
    forwardedFrom = f._id;
  }

  const mentions = (input.mentions || []).filter(id => c.members.some(m => String(m) === String(id)));

  if (String(env.E2EE_REQUIRED || 'true').toLowerCase() !== 'false' && !input.encryptedPayload) {
    throw new ApiError(400, 'End-to-end encrypted payload is required');
  }
  if (String(env.E2EE_REQUIRED || 'true').toLowerCase() !== 'false' && input.attachments?.length) {
    throw new ApiError(400, 'In E2EE mode, attachment metadata must be inside the encrypted message body');
  }

  const data = {
    conversation: c._id,
    sender: req.user.id,
    encryptedPayload: input.encryptedPayload || null,
    // Never persist a client-side plaintext duplicate when E2EE is enabled.
    text: String(env.E2EE_REQUIRED || 'true').toLowerCase() === 'false' ? input.text || '' : '',
    attachments: input.attachments || [],
    replyTo,
    forwardedFrom,
    mentions
  };

  if (c.disappearingAfterSeconds > 0) {
    data.expiresAt = new Date(Date.now() + c.disappearingAfterSeconds * 1000);
  }

  const m = await Message.create(data);
  c.lastMessageAt = m.createdAt;
  await c.save();

  const populated = await m.populate('sender', 'publicId username displayName avatarUrl');

  const io = req.app.get('io');
  if (io) {
    await emitToAuthorizedConversation(io, c, 'message:new', { conversationId: c.id, message: populated });
  }

  // Push notifications for offline members
  for (const member of c.members) {
    if (String(member) !== String(req.user.id)) {
      notifyUser(member, {
        title: populated.sender?.displayName || populated.sender?.username || 'Orbit',
        body: 'New encrypted message received',
        type: 'message',
        conversationId: c.id,
        url: `/chat?open=${c.id}`
      }).catch(() => {});
    }
  }

  // Mention notifications
  for (const mentionedId of mentions) {
    if (String(mentionedId) !== String(req.user.id)) {
      notifyUser(mentionedId, {
        title: `${populated.sender?.displayName || populated.sender?.username || 'Someone'} mentioned you`,
        body: 'You were mentioned in a message',
        type: 'mention',
        conversationId: c.id,
        url: `/chat?open=${c.id}`
      }).catch(() => {});
    }
  }

  ok(res, populated, 'Message sent', 201);
}

export async function editMessage(req, res) {
  const { m, c } = await accessibleMessage(req.params.id, req.user.id, req.device);
  if (String(m.sender) !== String(req.user.id)) throw new ApiError(403, 'Only sender can edit');
  if (m.deletedForEveryone) throw new ApiError(400, 'Message was deleted');
  if (Date.now() - m.createdAt.getTime() > 15 * 60 * 1000) throw new ApiError(403, 'Edit window expired');

  if (String(env.E2EE_REQUIRED || 'true').toLowerCase() !== 'false') {
    if (!req.body.encryptedPayload) throw new ApiError(400, 'Encrypted payload is required for edits');
    m.encryptedPayload = req.body.encryptedPayload;
    m.text = '';
  } else {
    if (typeof req.body.text !== 'string' || req.body.text.length > 10000) {
      throw new ApiError(400, 'text is required and must be <=10000 characters');
    }
    m.text = req.body.text;
  }
  m.editedAt = new Date();
  await m.save();
  if (req.app.get('io')) await emitToAuthorizedConversation(req.app.get('io'), c, 'message:updated', m);
  ok(res, m, 'Message edited');
}

export async function deleteMessage(req, res) {
  const { m, c } = await accessibleMessage(req.params.id, req.user.id, req.device);
  if (req.body.forEveryone === true) {
    if (String(m.sender) !== String(req.user.id)) throw new ApiError(403, 'Only sender can delete for everyone');
    m.deletedForEveryone = true;
    m.text = '';
    m.encryptedPayload = null;
    m.attachments = [];
  } else {
    m.deletedFor.addToSet(req.user.id);
  }
  await m.save();
  if (req.app.get('io')) await emitToAuthorizedConversation(req.app.get('io'), c, 'message:deleted', {
    messageId: m.id,
    forEveryone: m.deletedForEveryone,
    userId: req.user.id
  });
  ok(res, m, 'Message deleted');
}

export async function reactMessage(req, res) {
  const { m, c } = await accessibleMessage(req.params.id, req.user.id, req.device);
  const emoji = String(req.body.emoji || '').trim();
  if (!emoji || emoji.length > 32) throw new ApiError(400, 'Valid emoji required');
  m.reactions = m.reactions.filter(r => String(r.user) !== String(req.user.id) || r.emoji !== emoji);
  m.reactions.push({ user: req.user.id, emoji });
  await m.save();
  if (req.app.get('io')) await emitToAuthorizedConversation(req.app.get('io'), c, 'message:reaction', { messageId: m.id, reactions: m.reactions });
  ok(res, m, 'Reaction saved');
}

export async function readConversation(req, res) {
  assertObjectId(req.params.id, 'conversation ID');
  const c = await Conversation.findOne({ _id: req.params.id, members: req.user.id });
  if (!c) throw new ApiError(404, 'Conversation not found');
  if (!(await conversationAccess(c, req.user.id, req.device, 'new')).allowed) {
    throw new ApiError(403, 'This device is not authorized to access this conversation');
  }
  const userDoc = await User.findById(req.user.id).select('privacy');
  if (userDoc?.privacy?.readReceipts !== false) {
    await Message.updateMany(
      { conversation: c._id, sender: { $ne: req.user.id }, readBy: { $ne: req.user.id } },
      { $addToSet: { readBy: req.user.id, deliveredTo: req.user.id } }
    );
    if (req.app.get('io')) await emitToAuthorizedConversation(req.app.get('io'), c, 'receipt:read', { conversationId: c.id, userId: req.user.id });
  } else {
    await Message.updateMany(
      { conversation: c._id, sender: { $ne: req.user.id }, deliveredTo: { $ne: req.user.id } },
      { $addToSet: { deliveredTo: req.user.id } }
    );
  }
  ok(res, null, 'Conversation marked read');
}

export async function searchMessages(req, res) {
  if (String(env.E2EE_REQUIRED || 'true').toLowerCase() !== 'false') {
    throw new ApiError(400, 'Server-side text search is disabled for E2EE. Search decrypted messages locally on the client.');
  }
  assertObjectId(req.params.id, 'conversation ID');
  const c = await Conversation.findOne({ _id: req.params.id, members: req.user.id });
  if (!c) throw new ApiError(404, 'Conversation not found');

  if (!(await conversationAccess(c, req.user.id, req.device, 'new')).allowed) {
    throw new ApiError(403, 'This device is not authorized to search this conversation');
  }

  const q = String(req.query.q || '').trim();
  if (q.length < 2) throw new ApiError(400, 'Search query must be at least 2 characters');
  const messages = await Message.find({
    conversation: c._id,
    $text: { $search: q },
    deletedForEveryone: false,
    deletedFor: { $ne: req.user.id }
  }).sort({ createdAt: -1 }).limit(50).populate('sender', 'publicId username displayName avatarUrl');

  ok(res, messages, 'Search results');
}
