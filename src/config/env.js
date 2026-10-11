import 'dotenv/config';
import { z } from 'zod';
const schema=z.object({
 NODE_ENV:z.enum(['development','test','production']).default('development'),
 PORT:z.coerce.number().int().positive().default(5000),
 MONGODB_URI:z.string().min(1),
 JWT_SECRET:z.string().min(32),
 JWT_EXPIRES_IN:z.string().default('7d'),
 CLIENT_ORIGIN:z.string().default('http://localhost:5173'),
 REDIS_URL:z.string().optional(),
 SESSION_PREFIX:z.string().default('chat:session:'),
 E2EE_REQUIRED:z.string().default('true'),
 BCRYPT_ROUNDS:z.coerce.number().int().min(10).max(15).default(12),
 MAX_UPLOAD_MB:z.coerce.number().positive().max(100).default(20),
 OTP_TTL_MINUTES:z.coerce.number().int().positive().default(10),
 RESET_TTL_MINUTES:z.coerce.number().int().positive().default(15),
 SMTP_HOST:z.string().optional(), SMTP_PORT:z.coerce.number().default(587), SMTP_SECURE:z.string().default('false'),
 SMTP_USER:z.string().optional(), SMTP_PASS:z.string().optional(), SMTP_FROM:z.string().optional(),
 CLOUDINARY_CLOUD_NAME:z.string().optional(), CLOUDINARY_API_KEY:z.string().optional(), CLOUDINARY_API_SECRET:z.string().optional(),
 VAPID_PUBLIC_KEY:z.string().optional(), VAPID_PRIVATE_KEY:z.string().optional(), VAPID_SUBJECT:z.string().default('mailto:admin@example.com')
});
export const env=schema.parse(process.env);
