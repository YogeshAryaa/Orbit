import {Router} from 'express';
import mongoose from 'mongoose';
import {getRedis} from '../config/redis.js';
import {env} from '../config/env.js';
const r=Router();
r.get('/',async(req,res)=>{
 const dbOk=mongoose.connection.readyState===1;let redisStatus='development-memory',redisOk=true;
 if(getRedis()){try{await getRedis().ping();redisStatus='connected';}catch{redisOk=false;redisStatus='disconnected';}}
 else if(env.NODE_ENV==='production'){redisOk=false;redisStatus='required-but-not-configured';}
 const ready=dbOk&&redisOk;
 res.status(ready?200:503).json({success:ready,data:{database:dbOk?'connected':'disconnected',redis:redisStatus,uptimeSeconds:Math.floor(process.uptime())},message:'Health status'});
});
export default r;
