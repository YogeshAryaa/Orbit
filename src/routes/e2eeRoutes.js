import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import {
  registerDeviceKeys,
  listMyDevices,
  deleteMyDevice,
  updateDevicePermissions,
  revokeDevice,
  syncTab,
  updateTabStatus,
  authorizeHistoryEnvelopes,
  getUserKeyBundles,
  replenishOneTimePreKeys
} from '../controllers/e2eeController.js';

const r = Router();
r.use(requireAuth);

r.post('/devices', registerDeviceKeys);
r.get('/devices', listMyDevices);
r.patch('/devices/:deviceId/permissions', updateDevicePermissions);
r.post('/devices/:deviceId/revoke', revokeDevice);
r.delete('/devices/:deviceId', deleteMyDevice);
r.post('/devices/tabs/sync', syncTab);
r.patch('/devices/:deviceId/tabs/:tabId', updateTabStatus);
r.post('/devices/authorize-history', authorizeHistoryEnvelopes);
r.post('/devices/prekeys', replenishOneTimePreKeys);
r.get('/users/:userId/bundles', getUserKeyBundles);

export default r;
