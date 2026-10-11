import { createClient } from 'redis';
import { env } from './env.js';

let client;
let pubClient;
let subClient;
export async function connectRedis() {
  if (!env.REDIS_URL) {
    if (env.NODE_ENV === 'production') throw new Error('REDIS_URL is required in production for shared sessions, revocation, and Socket.IO scaling');
    console.warn('REDIS_URL not configured: using development-only in-memory session store and single-instance Socket.IO');
    return null;
  }
  client = createClient({ url: env.REDIS_URL });
  client.on('error', (err) => console.error(JSON.stringify({ level: 'error', event: 'redis_error', message: err.message })));
  await client.connect();
  pubClient = client.duplicate();
  subClient = client.duplicate();
  await Promise.all([pubClient.connect(), subClient.connect()]);
  console.log(JSON.stringify({ level: 'info', event: 'redis_connected' }));
  return { client, pubClient, subClient };
}
export function getRedis() { return client; }
export async function closeRedis() {
  await Promise.all([pubClient?.quit().catch(()=>{}), subClient?.quit().catch(()=>{}), client?.quit().catch(()=>{})]);
}
