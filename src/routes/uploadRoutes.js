import {Router} from 'express';import {uploadFile,uploadMiddleware} from '../controllers/uploadController.js';import {requireAuth} from '../middleware/auth.js';import {asyncHandler} from '../utils/asyncHandler.js';
const r=Router();r.post('/',requireAuth,(req,res,next)=>uploadMiddleware(req,res,e=>e?next(e):asyncHandler(uploadFile)(req,res,next)));export default r;
