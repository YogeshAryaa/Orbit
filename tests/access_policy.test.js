import test from 'node:test';
import assert from 'node:assert/strict';
import { conversationAccess, hideMessageContent } from '../src/services/accessPolicy.js';

const conversation = (overrides = {}) => ({
  _id: 'conversation-1',
  type: 'direct',
  memberAccessPolicies: [],
  ...overrides
});

const device = (overrides = {}) => ({
  status: 'authorized',
  linkStatus: 'approved',
  deviceId: 'device-1',
  historyAllowed: true,
  newMessagesAllowed: true,
  isPrimary: false,
  deviceType: 'browser',
  masterAuthorizations: [],
  ...overrides
});

test('access requires an authorized and approved device', async () => {
  assert.equal((await conversationAccess(conversation(), 'user-1', null)).allowed, false);
  assert.equal((await conversationAccess(conversation(), 'user-1', device({ linkStatus: 'pending' }))).allowed, false);
  assert.equal((await conversationAccess(conversation(), 'user-1', device({ status: 'revoked' }))).allowed, false);
});

test('device history and new-message permissions are enforced separately', async () => {
  const historyBlocked = device({ historyAllowed: false });
  assert.equal((await conversationAccess(conversation(), 'user-1', historyBlocked, 'history')).allowed, false);
  assert.equal((await conversationAccess(conversation(), 'user-1', historyBlocked, 'new')).allowed, true);
  assert.equal((await conversationAccess(conversation(), 'user-1', device({ newMessagesAllowed: false }), 'new')).allowed, false);
});

test('conversation modes and time-limited primary authorization are enforced', async () => {
  const selected = conversation({
    memberAccessPolicies: [{ user: 'user-1', mode: 'selected_devices', selectedDeviceIds: ['other-device'] }]
  });
  assert.equal((await conversationAccess(selected, 'user-1', device())).allowed, false);
  assert.equal((await conversationAccess(conversation({
    memberAccessPolicies: [{ user: 'user-1', mode: 'mobile_only', selectedDeviceIds: [] }]
  }), 'user-1', device({ isPrimary: true, deviceType: 'mobile' }))).allowed, true);
  const masterOnly = conversation({
    memberAccessPolicies: [{ user: 'user-1', mode: 'master_authorization', selectedDeviceIds: [] }]
  });
  assert.equal((await conversationAccess(masterOnly, 'user-1', device())).allowed, false);
  assert.equal((await conversationAccess(masterOnly, 'user-1', device({
    masterAuthorizations: [{ conversation: 'conversation-1', expiresAt: new Date(Date.now() + 60_000) }]
  }))).allowed, true);
  assert.equal((await conversationAccess(masterOnly, 'user-1', device({
    masterAuthorizations: [{ conversation: 'conversation-1', expiresAt: new Date(Date.now() - 1) }]
  }))).allowed, false);
});

test('group header-only mode blocks content access', async () => {
  assert.equal((await conversationAccess(conversation({ type: 'group', groupAccessMode: 'header_only' }), 'user-1', device())).allowed, false);
});

test('restricted message copies omit body, ciphertext, attachments, and nested message content', () => {
  const hidden = hideMessageContent({
    text: 'private text',
    encryptedPayload: { ciphertext: 'secret' },
    attachments: [{ url: 'private-url' }],
    replyTo: { text: 'quoted private text' },
    forwardedFrom: { encryptedPayload: { ciphertext: 'secret' } }
  });
  assert.equal('text' in hidden, false);
  assert.equal(hidden.encryptedPayload, null);
  assert.deepEqual(hidden.attachments, []);
  assert.equal(hidden.replyTo, null);
  assert.equal(hidden.forwardedFrom, null);
  assert.equal(hidden.accessRestricted, true);
});
