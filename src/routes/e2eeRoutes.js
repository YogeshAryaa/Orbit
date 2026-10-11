import {Router} from 'express';
import {requireAuth} from '../middleware/auth.js';
import {registerDeviceKeys,listMyDevices,deleteMyDevice,getUserKeyBundles,replenishOneTimePreKeys} from '../controllers/e2eeController.js';
const r=Router();r.use(requireAuth);r.post('/devices',registerDeviceKeys);r.get('/devices',listMyDevices);r.delete('/devices/:deviceId',deleteMyDevice);r.post('/devices/prekeys',replenishOneTimePreKeys);r.get('/users/:userId/bundles',getUserKeyBundles);export default r;
