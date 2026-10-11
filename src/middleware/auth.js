import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';
import User from '../models/User.js';
import { ApiError } from '../utils/ApiError.js';
import { isSessionActive } from '../services/tokenService.js';
export async function requireAuth(req,res,next){try{
 const h=req.headers.authorization||'',token=h.startsWith('Bearer ')?h.slice(7):null;
 if(!token)throw new ApiError(401,'Authentication required');
 const p=jwt.verify(token,env.JWT_SECRET);
 if(!await isSessionActive(p.sid,p.sub))throw new ApiError(401,'Session revoked or expired');
 const user=await User.findById(p.sub).select('-passwordHash');
 if(!user||user.status!=='active')throw new ApiError(401,'Invalid authentication');
 req.user=user;req.token=token;req.sessionId=p.sid;req.tokenExp=p.exp;next();
 }catch(e){next(e instanceof ApiError?e:new ApiError(401,'Invalid or expired token'));}}
