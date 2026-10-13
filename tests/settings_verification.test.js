import dns from 'node:dns';
dns.setServers(['8.8.8.8', '8.8.4.4']);
import request from 'supertest';
import app from '../src/app.js';
import { connectDB } from '../src/config/db.js';
import { connectRedis, closeRedis } from '../src/config/redis.js';
import { env } from '../src/config/env.js';
import mongoose from 'mongoose';

async function verifySettingsFixes() {
  console.log('Connecting to DB & Redis...');
  await connectRedis();
  await connectDB(env.MONGODB_URI);

  const testSuffix = 'v' + Date.now().toString(36);
  const userAData = {
    username: `verif_a_${testSuffix}`,
    displayName: `Verif A ${testSuffix}`,
    password: 'Password123!',
    email: `verif_a_${testSuffix}@example.com`,
    phone: `+1555${Math.floor(100000 + Math.random() * 900000)}`
  };
  const userBData = {
    username: `verif_b_${testSuffix}`,
    displayName: `Verif B ${testSuffix}`,
    password: 'Password123!',
    email: `verif_b_${testSuffix}@example.com`,
    phone: `+1555${Math.floor(100000 + Math.random() * 900000)}`
  };

  // Register User A & B
  const regA = await request(app).post('/api/auth/register').send(userAData);
  const tokenA = regA.body?.data?.token;
  const userA = regA.body?.data?.user;

  const regB = await request(app).post('/api/auth/register').send(userBData);
  const tokenB = regB.body?.data?.token;
  const userB = regB.body?.data?.user;

  console.log('--- 1. Testing safeUser contains email & phone ---');
  const meA = await request(app).get('/api/users/me').set('Authorization', `Bearer ${tokenA}`);
  console.log('User A email returned:', meA.body?.data?.email === userAData.email);
  console.log('User A phone returned:', meA.body?.data?.phone === userAData.phone);
  if (meA.body?.data?.email !== userAData.email) throw new Error('safeUser does not return email');

  console.log('--- 2. Testing clearing avatarUrl ---');
  // First set avatar
  await request(app).patch('/api/users/me').set('Authorization', `Bearer ${tokenA}`).send({ avatarUrl: 'https://example.com/pic.png' });
  const meWithAvatar = await request(app).get('/api/users/me').set('Authorization', `Bearer ${tokenA}`);
  console.log('Avatar set:', meWithAvatar.body?.data?.avatarUrl === 'https://example.com/pic.png');
  // Now clear avatar
  const clearRes = await request(app).patch('/api/users/me').set('Authorization', `Bearer ${tokenA}`).send({ avatarUrl: '' });
  console.log('Avatar cleared status:', clearRes.status);
  const meCleared = await request(app).get('/api/users/me').set('Authorization', `Bearer ${tokenA}`);
  console.log('Avatar is now empty:', meCleared.body?.data?.avatarUrl === '');
  if (meCleared.body?.data?.avatarUrl !== '') throw new Error('Avatar was not cleared');

  console.log('--- 3. Testing Change Password endpoint ---');
  // Wrong current password
  const badPass = await request(app)
    .post('/api/auth/password/change')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ currentPassword: 'WrongPassword!', newPassword: 'NewPassword999!' });
  console.log('Wrong password status:', badPass.status, badPass.body?.message);
  if (badPass.status !== 400) throw new Error('Failed to reject wrong current password');

  // Valid change password
  const goodPass = await request(app)
    .post('/api/auth/password/change')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ currentPassword: userAData.password, newPassword: 'NewPassword999!' });
  console.log('Good password change status:', goodPass.status, goodPass.body?.message);
  if (goodPass.status !== 200) throw new Error('Failed to change password');

  // Verify login with new password
  const loginNew = await request(app).post('/api/auth/login').send({ identifier: userAData.username, password: 'NewPassword999!' });
  console.log('Login with new password status:', loginNew.status);
  if (loginNew.status !== 200) throw new Error('Failed to login with new password');

  console.log('--- 4. Testing Profile Photo Privacy Enforcement ---');
  // Set User A profile photo to 'nobody'
  await request(app).patch('/api/users/me').set('Authorization', `Bearer ${tokenA}`).send({ avatarUrl: 'https://example.com/secret.png' });
  await request(app).patch('/api/users/me/privacy').set('Authorization', `Bearer ${tokenA}`).send({ profilePhoto: 'nobody' });
  // User B searches for User A
  const searchA = await request(app).get('/api/users/search').set('Authorization', `Bearer ${tokenB}`).query({ q: userAData.username });
  const foundA = searchA.body?.data?.[0];
  console.log('User B sees empty avatarUrl for User A:', foundA?.avatarUrl === '');
  if (foundA?.avatarUrl !== '') throw new Error('Profile photo leaked despite privacy=nobody');

  console.log('--- 5. Testing Moderation endpoint non-crash ---');
  const modRes = await request(app).get('/api/users/moderation/reports').set('Authorization', `Bearer ${tokenA}`);
  console.log('Moderation status (handled safely via Express):', modRes.status, modRes.body?.message);
  if (modRes.status !== 403) throw new Error('Moderation did not return 403');

  console.log('\n>>> ALL 5 SETTINGS FIXES VERIFIED SUCCESSFULLY! <<<');

  // Cleanup
  const User = mongoose.model('User');
  await User.deleteMany({ _id: { $in: [userA.id, userB.id] } });
  await closeRedis();
  await mongoose.disconnect();
}

verifySettingsFixes().catch(err => {
  console.error(err);
  process.exit(1);
});

