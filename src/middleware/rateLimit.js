import rateLimit from 'express-rate-limit';
import { RedisFixedWindowStore } from './redisRateLimitStore.js';
export const authLimiter=rateLimit({windowMs:15*60*1000,limit:30,standardHeaders:'draft-7',legacyHeaders:false,store:new RedisFixedWindowStore('auth'),message:{success:false,data:null,message:'Too many attempts. Try later.'}});
export const apiLimiter=rateLimit({windowMs:60*1000,limit:240,standardHeaders:'draft-7',legacyHeaders:false,store:new RedisFixedWindowStore('api')});
