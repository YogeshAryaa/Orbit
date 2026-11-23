import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import {
  registerDeviceKeys,
  authorizeDeviceLink,
  renameDevice,
  listMyDevices,
  deleteMyDevice,
  updateDevicePermissions,
  revokeDevice,
  syncTab,
  updateTabStatus,
  authorizeHistoryEnvelopes,
  getUserKeyBundles,
  replenishOneTimePreKeys,
  getKeyBackup,
  getAccountKeys,
  createAccountKeys,
  updateAccountKeyBackup,
  saveKeyBackup,
  updateEncryptionMode
} from '../controllers/e2eeController.js';
import {
  assignProfile,
  createProfile,
  deleteProfile,
  listProfiles,
  listSecurityActivity,
  updateProfile
} from '../controllers/privacyController.js';
import { asyncHandler } from '../utils/asyncHandler.js';

const r = Router();
r.use(requireAuth);

r.post('/devices', asyncHandler(registerDeviceKeys));
r.post('/devices/:deviceId/authorize-link', asyncHandler(authorizeDeviceLink));
r.patch('/devices/:deviceId', asyncHandler(renameDevice));
r.get('/devices', asyncHandler(listMyDevices));
r.patch('/devices/:deviceId/permissions', asyncHandler(updateDevicePermissions));
r.post('/devices/:deviceId/revoke', asyncHandler(revokeDevice));
r.delete('/devices/:deviceId', asyncHandler(deleteMyDevice));
r.post('/devices/tabs/sync', asyncHandler(syncTab));
r.patch('/devices/:deviceId/tabs/:tabId', asyncHandler(updateTabStatus));
r.post('/devices/authorize-history', asyncHandler(authorizeHistoryEnvelopes));
r.post('/devices/prekeys', asyncHandler(replenishOneTimePreKeys));
r.get('/account-keys', asyncHandler(getAccountKeys));
r.post('/account-keys', asyncHandler(createAccountKeys));
r.put('/account-keys/backup', asyncHandler(updateAccountKeyBackup));
r.get('/users/:userId/bundles', asyncHandler(getUserKeyBundles));
r.get('/key-backup', asyncHandler(getKeyBackup));
r.post('/key-backup', asyncHandler(saveKeyBackup));
r.patch('/encryption-mode', asyncHandler(updateEncryptionMode));
r.get('/profiles', asyncHandler(listProfiles));
r.post('/profiles', asyncHandler(createProfile));
r.patch('/profiles/:profileId', asyncHandler(updateProfile));
r.delete('/profiles/:profileId', asyncHandler(deleteProfile));
r.patch('/devices/:deviceId/profile', asyncHandler(assignProfile));
r.get('/security-activity', asyncHandler(listSecurityActivity));

export default r;
