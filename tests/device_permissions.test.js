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
import {
  createDeviceKeyMaterial,
  encryptMessage,
  decryptMessage,
  extractContentKey,
  createEnvelopeForDevice
} from '../client-examples/e2ee.js';

test('Device & Tab-based message visibility permissions end-to-end', async () => {
  await connectRedis();
  await connectDB(env.MONGODB_URI);

  const suffix = 'dp' + Date.now().toString(36);
  const userAData = {
    username: `devperm_${suffix}`,
    displayName: `DevPerm ${suffix}`,
    password: 'Password123!',
    email: `devperm_${suffix}@example.com`,
    phone: `+1555${Math.floor(100000 + Math.random() * 900000)}`
  };
  const userBData = {
    username: `devb_${suffix}`,
    displayName: `DevB ${suffix}`,
    password: 'Password123!',
    email: `devb_${suffix}@example.com`,
    phone: `+1555${Math.floor(100000 + Math.random() * 900000)}`
  };

  // Register User A and User B
  const regA = await request(app).post('/api/auth/register').send(userAData);
  const tokenA = regA.body?.data?.token;
  const userA = regA.body?.data?.user;

  const regB = await request(app).post('/api/auth/register').send(userBData);
  const tokenB = regB.body?.data?.token;
  const userB = regB.body?.data?.user;

  // 1. User A registers Device 1 (first device -> gets historyAllowed: true)
  const dev1 = await createDeviceKeyMaterial(`dev1_${suffix}`, 5);
  const regDev1Res = await request(app)
    .post('/api/e2ee/devices')
    .set('Authorization', `Bearer ${tokenA}`)
    .set('X-Device-Id', `dev1_${suffix}`)
    .send(dev1.publicRegistration);
  assert.equal(regDev1Res.status, 200);
  assert.equal(regDev1Res.body?.data?.historyAllowed, true, 'First device must have historyAllowed: true');
  assert.equal(regDev1Res.body?.data?.newMessagesAllowed, true);
  assert.equal(regDev1Res.body?.data?.status, 'authorized');

  // Register Device for User B so we can start conversation
  const devB = await createDeviceKeyMaterial(`devB_${suffix}`, 5);
  await request(app)
    .post('/api/e2ee/devices')
    .set('Authorization', `Bearer ${tokenB}`)
    .set('X-Device-Id', `devB_${suffix}`)
    .send(devB.publicRegistration);

  // Create conversation between User A and User B
  const convRes = await request(app)
    .post('/api/conversations')
    .set('Authorization', `Bearer ${tokenA}`)
    .set('X-Device-Id', `dev1_${suffix}`)
    .send({ memberIds: [userB.id], type: 'direct' });
  assert.equal(convRes.status, 201);
  const convId = convRes.body?.data?._id;

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
  const dev2 = await createDeviceKeyMaterial(`dev2_${suffix}`, 5);
  const regDev2Res = await request(app)
    .post('/api/e2ee/devices')
    .set('Authorization', `Bearer ${tokenA}`)
    .set('X-Device-Id', `dev2_${suffix}`)
    .send(dev2.publicRegistration);
  assert.equal(regDev2Res.status, 200);
  assert.equal(regDev2Res.body?.data?.historyAllowed, false, 'Secondary device must default to historyAllowed: false');
  assert.equal(regDev2Res.body?.data?.newMessagesAllowed, true);

  // 3. Device 2 attempts to fetch historical messages -> server filters them out!
  const dev2MsgRes = await request(app)
    .get(`/api/conversations/${convId}/messages`)
    .set('Authorization', `Bearer ${tokenA}`)
    .set('X-Device-Id', `dev2_${suffix}`);
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

  // 5. Device 2 now fetches historical messages -> message returned & decryptable!
  const dev2MsgAfterAuth = await request(app)
    .get(`/api/conversations/${convId}/messages`)
    .set('Authorization', `Bearer ${tokenA}`)
    .set('X-Device-Id', `dev2_${suffix}`);
  assert.equal(dev2MsgAfterAuth.status, 200);
  assert.equal(dev2MsgAfterAuth.body?.data?.length, 1);
  const decryptedOnDev2 = await decryptMessage(dev2MsgAfterAuth.body.data[0].encryptedPayload, `dev2_${suffix}`, dev2.privateJwks);
  assert.equal(decryptedOnDev2, 'Historical message from Device 1');

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
    .set('Authorization', `Bearer ${tokenA}`)
    .set('X-Device-Id', `dev2_${suffix}`);
  assert.equal(blockedFetch.body?.data?.length, 0);

  // 7. Test Tab Sync
  const tabSyncRes = await request(app)
    .post('/api/e2ee/devices/tabs/sync')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ deviceId: `dev1_${suffix}`, tabId: 'tab-alpha-1', title: 'Main Chat', status: 'active' });
  assert.equal(tabSyncRes.status, 200);
  assert.ok(Array.isArray(tabSyncRes.body?.data));
  assert.equal(tabSyncRes.body?.data?.[0]?.tabId, 'tab-alpha-1');

  // 8. Test Revoke Device 2
  const revokeRes = await request(app)
    .post(`/api/e2ee/devices/dev2_${suffix}/revoke`)
    .set('Authorization', `Bearer ${tokenA}`);
  assert.equal(revokeRes.status, 200);
  assert.equal(revokeRes.body?.data?.status, 'revoked');

  // Subsequent request from revoked device returns 401
  const revokedReq = await request(app)
    .get(`/api/conversations/${convId}/messages`)
    .set('Authorization', `Bearer ${tokenA}`)
    .set('X-Device-Id', `dev2_${suffix}`);
  assert.equal(revokedReq.status, 401);

  await mongoose.disconnect();
  await closeRedis();
});

