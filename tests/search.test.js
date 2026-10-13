import dns from 'dns';
dns.setServers(['8.8.8.8', '8.8.4.4']);
import mongoose from 'mongoose';
import { env } from '../src/config/env.js';
import User from '../src/models/User.js';
import Conversation from '../src/models/Conversation.js';
import { searchUsers } from '../src/controllers/userController.js';

async function run() {
  console.log('Connecting to MongoDB...');
  await mongoose.connect(env.MONGODB_URI);

  // Find or create test users
  const userA = await User.findOne({ username: 'yog' });
  const userB = await User.findOne({ username: 'abc' });
  const userC = await User.findOne({ username: 'sefi1' });

  if (!userA || !userB) {
    console.error('Test users not found in DB');
    process.exit(1);
  }

  console.log('Testing searchUsers controller directly...');

  const executeSearch = async (reqUser, queryStr) => {
    return new Promise((resolve, reject) => {
      const req = {
        user: reqUser,
        validated: { query: { q: queryStr } }
      };
      const res = {
        status: () => res,
        json: (payload) => resolve(payload.data)
      };
      searchUsers(req, res).catch(reject);
    });
  };

  // Test 1: User A searches for User B by phone without country code
  const r1 = await executeSearch(userA, '9407129209');
  console.log('1. Search by 10-digit phone (9407129209):', r1.map(u => u.username));
  if (!r1.some(u => u.username === 'abc')) throw new Error('Failed to find User B by phone');

  // Test 2: User A searches for User B by phone WITH +91
  const r2 = await executeSearch(userA, '+919407129209');
  console.log('2. Search by +91 phone (+919407129209):', r2.map(u => u.username));
  if (!r2.some(u => u.username === 'abc')) throw new Error('Failed to find User B with +91');

  // Test 3: User B searches for User A by @username
  const r3 = await executeSearch(userB, '@yog');
  console.log('3. Search by @username (@yog):', r3.map(u => u.username));
  if (!r3.some(u => u.username === 'yog')) throw new Error('Failed to find User A by @yog');

  // Test 4: Search by Public ID lowercase
  const r4 = await executeSearch(userB, userA.publicId.toLowerCase());
  console.log(`4. Search by publicId (${userA.publicId.toLowerCase()}):`, r4.map(u => u.username));
  if (!r4.some(u => u.username === 'yog')) throw new Error('Failed to find User A by publicId');

  // Test 5: Search for self (User A searches own phone 8770057232)
  const r5 = await executeSearch(userA, '8770057232');
  console.log('5. Search self by phone (8770057232):', r5.map(u => `${u.username} - isSelf: ${u.isSelf} - name: ${u.displayName}`));
  if (!r5.some(u => u.username === 'yog' && u.isSelf === true)) throw new Error('Failed to find self in search');

  // Test 6: Search by display name substring
  const r6 = await executeSearch(userA, 'Sefi');
  console.log('6. Search by display name (Sefi):', r6.map(u => u.username));
  if (!r6.some(u => u.username === 'sefi1')) throw new Error('Failed to find Sefi by display name');

  console.log('\n>>> ALL SEARCH TESTS PASSED SUCCESSFULLY! <<<');
  process.exit(0);
}

run().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});

