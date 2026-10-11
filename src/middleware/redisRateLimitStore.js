import { getRedis } from '../config/redis.js';
const local = new Map();
export class RedisFixedWindowStore {
 constructor(namespace) { this.prefix = `chat:ratelimit:${namespace}:`; this.windowMs = 60000; }
 init(options) { this.windowMs = options.windowMs; }
 async increment(key) {
  const redis = getRedis();
  if (!redis) {
   const k=this.prefix+key, now=Date.now(); let v=local.get(k);
   if(!v||v.resetAt<=now)v={hits:0,resetAt:now+this.windowMs};
   v.hits++;local.set(k,v);return {totalHits:v.hits,resetTime:new Date(v.resetAt)};
  }
  const k=this.prefix+key;const hits=await redis.incr(k);if(hits===1)await redis.pExpire(k,this.windowMs);const ttl=await redis.pTTL(k);return {totalHits:hits,resetTime:new Date(Date.now()+Math.max(ttl,0))};
 }
 async decrement(key) { const redis=getRedis();const k=this.prefix+key;if(redis){const n=await redis.decr(k);if(n<=0)await redis.del(k);}else{const v=local.get(k);if(v){v.hits--;if(v.hits<=0)local.delete(k);}} }
 async resetKey(key) { const redis=getRedis();const k=this.prefix+key;if(redis)await redis.del(k);else local.delete(k); }
}
