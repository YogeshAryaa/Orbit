import {Router} from 'express';import {createStatus,getMyStatuses,getAllStatuses,viewStatus,deleteStatus} from '../controllers/statusController.js';import {requireAuth} from '../middleware/auth.js';import {validate} from '../middleware/validate.js';import {statusSchema} from '../validators/schemas.js';import {asyncHandler} from '../utils/asyncHandler.js';
const r=Router();
r.use(requireAuth);
r.post('/',validate(statusSchema),asyncHandler(createStatus));
r.get('/mine',asyncHandler(getMyStatuses));
r.get('/all',asyncHandler(getAllStatuses));
r.post('/:id/view',asyncHandler(viewStatus));
r.delete('/:id',asyncHandler(deleteStatus));
export default r;
