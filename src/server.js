
import dns from 'node:dns';

dns.setServers(['8.8.8.8', '8.8.4.4']);

import http from 'node:http';
import { Server } from 'socket.io';
import { createAdapter } from '@socket.io/redis-adapter';
import app from './app.js';
import { env } from './config/env.js';
import { connectDB } from './config/db.js';
import { connectRedis, closeRedis } from './config/redis.js';
import { cloudinaryEnabled } from './config/cloudinary.js';
import { configureSockets } from './sockets/index.js';

if (env.NODE_ENV === 'production' && !cloudinaryEnabled) throw new Error('Cloudinary (or an equivalent shared object-storage adapter) must be configured in production for multi-instance media uploads');
const redis = await connectRedis();
await connectDB(env.MONGODB_URI);
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: env.CLIENT_ORIGIN.split(',').map(v=>v.trim()), credentials: true }, maxHttpBufferSize: 3e6, pingInterval: 25000, pingTimeout: 20000 });
if (redis) io.adapter(createAdapter(redis.pubClient, redis.subClient));
app.set('io', io);
configureSockets(io);
server.listen(env.PORT, () => console.log(JSON.stringify({ level: 'info', event: 'server_started', port: env.PORT, mode: env.NODE_ENV, redisAdapter: Boolean(redis) })));
async function shutdown(signal) {
 console.log(JSON.stringify({ level:'info', event:'shutdown', signal }));
 io.close(); server.close(async()=>{ await closeRedis(); process.exit(0); });
 setTimeout(()=>process.exit(1),10000).unref();
}
process.on('SIGTERM',()=>shutdown('SIGTERM'));
process.on('SIGINT',()=>shutdown('SIGINT'));
