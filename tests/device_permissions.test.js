import dns from 'node:dns';
dns.setServers(['8.8.8.8', '8.8.4.4']);
import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import app from '../src/app.js';
import { connectDB } from '../src/config/db.js';
import { connectRedis, closeRedis } from '../src/config/redis.js';
import { env } from '../src/config/env.js';
import mongoose from 'mongoose';
import { createPrivateKey, sign } from 'node:crypto';
import fs from 'node:fs/promises';
import ProtectedUpload from '../src/models/ProtectedUpload.js';
import { cloudinaryEnabled } from '../src/config/cloudinary.js';
import {
  createDeviceKeyMaterial,
  encryptMessage,
  decryptMessage,
  extractContentKey,
  createEnvelopeForDevice
} from '../client-examples/e2ee.js';

test('Device & Tab-based message visibility permissions end-to-end', async (t) => {
  let uploadedAssetId;
  await connectRedis();
  await connectDB(env.MONGODB_URI);
  t.after(async () => {
    if (uploadedAssetId) {
      const asset = await ProtectedUpload.findById(uploadedAssetId);
      if (asset?.storage === 'local') await fs.unlink(asset.storageKey);
      await ProtectedUpload.deleteOne({ _id: uploadedAssetId });
    }
    await closeRedis();
    await mongoose.disconnect();
  });

  const suffix = 'dp' + Date.now().toString(36);
  const primaryDeviceId = `dev1_${suffix}`;
  const secondaryDeviceId = `dev2_${suffix}`;
  const deviceBId = `devB_${suffix}`;
  const dev1 = await createDeviceKeyMaterial(primaryDeviceId, 5);
  const dev2 = await createDeviceKeyMaterial(secondaryDeviceId, 5);
  const devB = await createDeviceKeyMaterial(deviceBId, 5);
  const userAData = {
    username: `devperm_${suffix}`,
    displayName: `DevPerm ${suffix}`,
    password: 'Password123!',
    email: `devperm_${suffix}@example.com`,
    phone: `+1555${Math.floor(100000 + Math.random() * 900000)}`,
    deviceId: primaryDeviceId
  };
  const userBData = {
    username: `devb_${suffix}`,
    displayName: `DevB ${suffix}`,
    password: 'Password123!',
    email: `devb_${suffix}@example.com`,
    phone: `+1555${Math.floor(100000 + Math.random() * 900000)}`,
    deviceId: deviceBId
  };

  // Register User A and User B
  const regA = await request(app).post('/api/auth/register').send(userAData);
  const tokenA = regA.body?.data?.token;
  const userA = regA.body?.data?.user;

  const regB = await request(app).post('/api/auth/register').send(userBData);
  const tokenB = regB.body?.data?.token;
  const userB = regB.body?.data?.user;

  // 1. User A registers Device 1 (first device -> gets historyAllowed: true)
  const regDev1Res = await request(app)
    .post('/api/e2ee/devices')
    .set('Authorization', `Bearer ${tokenA}`)
    .set('X-Device-Id', primaryDeviceId)
    .send({ ...dev1.publicRegistration, deviceId: primaryDeviceId });
  assert.equal(regDev1Res.status, 200);
  assert.equal(regDev1Res.body?.data?.historyAllowed, true, 'First device must have historyAllowed: true');
  assert.equal(regDev1Res.body?.data?.newMessagesAllowed, true);
  assert.equal(regDev1Res.body?.data?.status, 'authorized');

  // Register Device for User B so we can start conversation
  await request(app)
    .post('/api/e2ee/devices')
    .set('Authorization', `Bearer ${tokenB}`)
    .set('X-Device-Id', deviceBId)
    .send({ ...devB.publicRegistration, deviceId: deviceBId });

  // Create conversation between User A and User B
  const convRes = await request(app)
    .post('/api/conversations')
    .set('Authorization', `Bearer ${tokenA}`)
    .set('X-Device-Id', `dev1_${suffix}`)
    .send({ memberIds: [userB.id], type: 'direct' });
  assert.equal(convRes.status, 201);
  const convId = convRes.body?.data?._id;
  const groupRes = await request(app)
    .post('/api/conversations')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ memberIds: [userB.id], type: 'group', title: `Privacy ${suffix}` });
  assert.equal(groupRes.status, 201);
  const groupId = groupRes.body?.data?._id;
  const groupLock = await request(app)
    .patch(`/api/conversations/${groupId}/access/group`)
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ mode: 'header_only' });
  assert.equal(groupLock.status, 200);
  const nonAdminGroupLock = await request(app)
    .patch(`/api/conversations/${groupId}/access/group`)
    .set('Authorization', `Bearer ${tokenB}`)
    .send({ mode: 'full_decryption' });
  assert.equal(nonAdminGroupLock.status, 403);
  const profileRes = await request(app)
    .post('/api/e2ee/profiles')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ name: 'Approved conversations', allowedConversations: [convId], allowedGroups: [groupId] });
  assert.equal(profileRes.status, 201);
  const profileId = profileRes.body?.data?._id;
  if (!cloudinaryEnabled) {
    const encryptedBytes = Buffer.from('test encrypted media');
    const uploadRes = await request(app)
      .post('/api/uploads')
      .set('Authorization', `Bearer ${tokenA}`)
      .set('X-Device-Id', primaryDeviceId)
      .field('conversationId', convId)
      .attach('file', encryptedBytes, { filename: 'test.enc', contentType: 'application/octet-stream' });
    assert.equal(uploadRes.status, 201);
    uploadedAssetId = uploadRes.body?.data?.publicId;
    const downloadRes = await request(app)
      .get(`/api/uploads/${uploadedAssetId}`)
      .set('Authorization', `Bearer ${tokenA}`)
      .set('X-Device-Id', primaryDeviceId);
    assert.equal(downloadRes.status, 200);
    assert.deepEqual(downloadRes.body, encryptedBytes);
  }

  // Device 1 sends historical message
  const dev1Bundle = { ...dev1.publicRegistration, userId: userA.id, oneTimePreKey: dev1.publicRegistration.oneTimePreKeys[0] };
  const devBBundle = { ...devB.publicRegistration, userId: userB.id, oneTimePreKey: devB.publicRegistration.oneTimePreKeys[0] };
  const payload1 = await encryptMessage('Historical message from Device 1', `dev1_${suffix}`, [dev1Bundle, devBBundle]);

  const sendRes = await request(app)
    .post('/api/messages')
    .set('Authorization', `Bearer ${tokenA}`)
    .set('X-Device-Id', `dev1_${suffix}`)
    .send({ conversationId: convId, encryptedPayload: payload1 });
  assert.equal(sendRes.status, 201);
  const msg1Id = sendRes.body?.data?._id;

  // 2. User A logs in on Device 2 (secondary device -> default historyAllowed: false)
  const loginDev2 = await request(app).post('/api/auth/login').send({
    identifier: userAData.username,
    password: userAData.password,
    deviceId: secondaryDeviceId
  });
  const tokenA2 = loginDev2.body?.data?.token;
  const regDev2Res = await request(app)
    .post('/api/e2ee/devices')
    .set('Authorization', `Bearer ${tokenA2}`)
    .set('X-Device-Id', secondaryDeviceId)
    .send({ ...dev2.publicRegistration, deviceId: secondaryDeviceId });
  assert.equal(regDev2Res.status, 200);
  assert.equal(regDev2Res.body?.data?.historyAllowed, false, 'Secondary device must default to historyAllowed: false');
  assert.equal(regDev2Res.body?.data?.linkStatus, 'pending');
  const linkMessage = [
    'orbit-device-link-v1',
    String(userA.id),
    secondaryDeviceId,
    regDev2Res.body.data.identityPublicKey,
    regDev2Res.body.data.linkChallenge
  ].join('\n');
  const signingKey = createPrivateKey({ key: dev1.privateJwks.identityPrivateKey, format: 'jwk' });
  const linkSignature = sign('sha256', Buffer.from(linkMessage), { key: signingKey, dsaEncoding: 'ieee-p1363' }).toString('base64');
  const approveLink = await request(app)
    .post(`/api/e2ee/devices/${secondaryDeviceId}/authorize-link`)
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ signature: linkSignature });
  assert.equal(approveLink.status, 200);
  const assignProfile = await request(app)
    .patch(`/api/e2ee/devices/${secondaryDeviceId}/profile`)
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ profileId });
  assert.equal(assignProfile.status, 200);
  const setMasterMode = await request(app)
    .patch(`/api/conversations/${convId}/access`)
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ mode: 'master_authorization' });
  assert.equal(setMasterMode.status, 200);
  const temporaryAccess = await request(app)
    .post(`/api/conversations/${convId}/access/authorize-device`)
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ deviceId: secondaryDeviceId, minutes: 15 });
  assert.equal(temporaryAccess.status, 200);
  const lockedGroupAccess = await request(app)
    .get(`/api/conversations/${groupId}/access`)
    .set('Authorization', `Bearer ${tokenA2}`)
    .set('X-Device-Id', secondaryDeviceId);
  assert.equal(lockedGroupAccess.status, 200);
  assert.equal(lockedGroupAccess.body?.data?.effectiveAccess, 'header_only');
  if (uploadedAssetId) {
    const deniedDownload = await request(app)
      .get(`/api/uploads/${uploadedAssetId}`)
      .set('Authorization', `Bearer ${tokenA2}`)
      .set('X-Device-Id', secondaryDeviceId);
    assert.equal(deniedDownload.status, 403);
  }

  // 3. Device 2 attempts to fetch historical messages -> server filters them out!
  const dev2MsgRes = await request(app)
    .get(`/api/conversations/${convId}/messages`)
    .set('Authorization', `Bearer ${tokenA2}`)
    .set('X-Device-Id', secondaryDeviceId);
  assert.equal(dev2MsgRes.status, 200);
  assert.equal(dev2MsgRes.body?.data?.length, 0, 'Device 2 must NOT receive historical messages when historyAllowed: false');

  // Verify Device 1 still fetches the historical message normally
  const dev1MsgRes = await request(app)
    .get(`/api/conversations/${convId}/messages`)
    .set('Authorization', `Bearer ${tokenA}`)
    .set('X-Device-Id', `dev1_${suffix}`);
  assert.equal(dev1MsgRes.status, 200);
  assert.equal(dev1MsgRes.body?.data?.length, 1);
  assert.equal(dev1MsgRes.body?.data?.[0]?._id, msg1Id);

  // 4. Device 1 authorizes Device 2 for history via key authorization
  const rawKey = await extractContentKey(payload1, `dev1_${suffix}`, dev1.privateJwks);
  const dev2Bundle = { ...dev2.publicRegistration, userId: userA.id, signedPreKeyPublic: dev2.publicRegistration.signedPreKeyPublic };
  const dev2Env = await createEnvelopeForDevice(rawKey, dev2Bundle);

  const authHistRes = await request(app)
    .post('/api/e2ee/devices/authorize-history')
    .set('Authorization', `Bearer ${tokenA}`)
    .set('X-Device-Id', `dev1_${suffix}`)
    .send({
      targetDeviceId: `dev2_${suffix}`,
      envelopes: [{ messageId: msg1Id, envelope: dev2Env }]
    });
  assert.equal(authHistRes.status, 200);
  assert.equal(authHistRes.body?.data?.historyAllowed, true);
  assert.equal(authHistRes.body?.data?.updatedCount, 1);
  if (uploadedAssetId) {
    const allowedDownload = await request(app)
      .get(`/api/uploads/${uploadedAssetId}`)
      .set('Authorization', `Bearer ${tokenA2}`)
      .set('X-Device-Id', secondaryDeviceId);
    assert.equal(allowedDownload.status, 200);
  }

  // 5. Device 2 now fetches historical messages -> message returned & decryptable!
  const dev2MsgAfterAuth = await request(app)
    .get(`/api/conversations/${convId}/messages`)
    .set('Authorization', `Bearer ${tokenA2}`)
    .set('X-Device-Id', secondaryDeviceId);
  assert.equal(dev2MsgAfterAuth.status, 200);
  assert.equal(dev2MsgAfterAuth.body?.data?.length, 1);
  const decryptedOnDev2 = await decryptMessage(dev2MsgAfterAuth.body.data[0].encryptedPayload, `dev2_${suffix}`, dev2.privateJwks);
  assert.equal(decryptedOnDev2, 'Historical message from Device 1');

  const selectedPolicy = await request(app)
    .patch(`/api/conversations/${convId}/access`)
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ mode: 'selected_devices', selectedDeviceIds: [primaryDeviceId] });
  assert.equal(selectedPolicy.status, 200);
  const restrictedMessages = await request(app)
    .get(`/api/conversations/${convId}/messages`)
    .set('Authorization', `Bearer ${tokenA2}`)
    .set('X-Device-Id', secondaryDeviceId);
  assert.equal(restrictedMessages.status, 200);
  assert.equal(restrictedMessages.body?.data?.[0]?.accessRestricted, true);
  assert.equal(restrictedMessages.body?.data?.[0]?.encryptedPayload, null);
  const restrictedReaction = await request(app)
    .post(`/api/messages/${msg1Id}/reactions`)
    .set('Authorization', `Bearer ${tokenA2}`)
    .set('X-Device-Id', secondaryDeviceId)
    .send({ emoji: '👍' });
  assert.equal(restrictedReaction.status, 403);

  // 6. Test Policy Change: 'block'
  const blockRes = await request(app)
    .patch(`/api/e2ee/devices/dev2_${suffix}/permissions`)
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ policy: 'block' });
  assert.equal(blockRes.status, 200);
  assert.equal(blockRes.body?.data?.status, 'fully_blocked');
  assert.equal(blockRes.body?.data?.newMessagesAllowed, false);
  assert.equal(blockRes.body?.data?.historyAllowed, false);

  // Blocked device cannot retrieve messages
  const blockedFetch = await request(app)
    .get(`/api/conversations/${convId}/messages`)
    .set('Authorization', `Bearer ${tokenA2}`)
    .set('X-Device-Id', secondaryDeviceId);
  assert.equal(blockedFetch.body?.data?.length, 0);

  // 7. Test Tab Sync
  const tabSyncRes = await request(app)
    .post('/api/e2ee/devices/tabs/sync')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ deviceId: primaryDeviceId, tabId: 'tab-alpha-1', title: 'Main Chat', status: 'active' });
  assert.equal(tabSyncRes.status, 200);
  assert.ok(Array.isArray(tabSyncRes.body?.data));
  assert.equal(tabSyncRes.body?.data?.[0]?.tabId, 'tab-alpha-1');

  // 8. Test Revoke Device 2
  const revokeRes = await request(app)
    .post(`/api/e2ee/devices/${secondaryDeviceId}/revoke`)
    .set('Authorization', `Bearer ${tokenA}`);
  assert.equal(revokeRes.status, 200);
  assert.equal(revokeRes.body?.data?.status, 'revoked');

  // Subsequent request from revoked device returns 401
  const revokedReq = await request(app)
    .get(`/api/conversations/${convId}/messages`)
    .set('Authorization', `Bearer ${tokenA2}`)
    .set('X-Device-Id', secondaryDeviceId);
  assert.equal(revokedReq.status, 401);

});
