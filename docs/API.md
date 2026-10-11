# API Reference v2
Base: `/api`. Response envelope: `{success,data,message}`. Protected routes use `Authorization: Bearer <JWT>`. IDs are MongoDB ObjectIds unless specified.

## Health and auth
- `GET /health` public: DB state/uptime; `503` if DB unavailable.
- `POST /auth/register` public, rate limited. JSON `{username,displayName,password,email?,phone?}`. `201 {user,token}`. Errors `400,409,429`.
- `POST /auth/login` public, rate limited. `{identifier,password}`. `200 {user,token}`. Errors `400,401,429`.
- `POST /auth/logout` JWT required. Invalidates token in this process. Errors `401`.
- `POST /auth/email/verification-code` JWT required. Sends verification OTP to the current user's email. Requires SMTP and user email. Errors `400,503`.
- `POST /auth/email/verify` public. `{email,code}`. Verifies email. Errors `400`.
- `POST /auth/password/reset/request` public/rate limited. `{email}`. Sends reset code. Requires SMTP. Errors `404,503,429`.
- `POST /auth/password/reset` public/rate limited. `{email,code,newPassword}`. Errors `400,429`.

## Users
- `GET /users/me` JWT: safe profile.
- `PATCH /users/me` JWT: optional `{displayName,bio,avatarUrl,statusMessage,discoverableByPhone}`. `avatarUrl` must be URL.
- `PATCH /users/me/privacy` JWT: `{lastSeen:"everyone|contacts|nobody",profilePhoto:"everyone|contacts|nobody",readReceipts:boolean,discoverableByPhone?:boolean}`.
- `GET /users/search?q=...` JWT: exact match by publicId, username, or phone only when target enabled phone discovery; does not expose phone/email.
- `POST /users/:id/block` and `DELETE /users/:id/block` JWT: block/unblock.
- `POST /users/:id/report` JWT `{reason}`: report user.
- `POST /users/push-subscriptions` JWT `{endpoint,keys:{p256dh,auth}}`; `DELETE /users/push-subscriptions` JWT `{endpoint}`.
- `GET /users/moderation/reports?status=open` JWT moderator only; `PATCH /users/moderation/reports/:id` JWT moderator only `{status:"reviewing|resolved|dismissed"}`. Set `MODERATOR_IDS` environment variable to comma-separated Mongo IDs.

## Conversations/groups
- `GET /conversations` JWT: lists non-archived conversations and unread counts.
- `POST /conversations` JWT `{memberIds:[ObjectId],type:"direct|group",title?}`. Direct requires exactly one other member and reuses existing conversation.
- `GET /conversations/:id/messages?limit=30&before=<ISO>` JWT membership required. `limit` 1–100.
- `GET /conversations/:id/search?q=words` JWT membership required. Full-text search.
- `PATCH /conversations/:id/group` JWT group admin `{title?,disappearingAfterSeconds?:0|3600|86400|604800|2592000}`.
- `POST /conversations/:id/members` JWT group admin `{memberIds:[ObjectId]}`.
- `DELETE /conversations/:id/members/:memberId` JWT group admin.
- `POST /conversations/:id/leave` JWT group member.
- `PATCH /conversations/:id/pin` and `/conversations/:id/archive` are intended to accept `{enabled:boolean}`. (Use `POST` routes noted below if your client needs stable API; implementation route registration is version-dependent.)

## Messages
- `POST /messages` JWT `{conversationId,text?,attachments?,replyTo?,forwardedFrom?}`; text or attachments required. `201`. Validates conversation membership and reply source.
- `PATCH /messages/:id` JWT sender only; `{text}`; 15-minute edit window.
- `DELETE /messages/:id` JWT `{forEveryone:boolean}`; sender-only for everyone, otherwise deletes for current user.
- `POST /messages/:id/reactions` JWT `{emoji}`.
- `POST /messages/read/:id` JWT, `:id` is conversation ID; marks incoming messages read.
- `PATCH /messages/:id/pin` JWT `{enabled:boolean}`.
- `GET /conversations/:id/search?q=...` JWT membership required, up to 50 text search results.

## Uploads
- `POST /uploads` JWT multipart `file`. Allowed images, selected video/audio, PDF, text, zip, DOCX/XLSX. Max `MAX_UPLOAD_MB`. Cloudinary if configured, local development otherwise. Errors `400,413,415`.

## Socket.IO
Connect with `io(origin,{auth:{token}})`. Token checked at handshake. Socket.IO reconnects automatically; rejoin conversation rooms after reconnect.
Client events:
- `conversation:join` `{conversationId}`; ack `{success,data}`.
- `typing:start`, `typing:stop` `{conversationId}`; ack `{success}`; other room members receive `typing:update`.
- `message:delivered` `{conversationId,messageIds:[...]}`; ack `{success}`; room gets `receipt:delivered`.
- `call:signal` `{conversationId,signal:{type:"offer|answer|ice-candidate|reject|busy|end",...}}`; direct chats only; recipient gets `call:signal`.
Server events: `message:new`, `message:updated`, `message:deleted`, `message:reaction`, `receipt:read`, `receipt:delivered`, `presence:online`, `presence:offline`, `typing:update`, `call:signal`.

## Axios example
```js
import axios from 'axios';
export const api = axios.create({baseURL:'http://localhost:5000/api'});
api.interceptors.request.use(c=>{const t=localStorage.getItem('chat_token');if(t)c.headers.Authorization=`Bearer ${t}`;return c;});
```
## Socket example
```js
import {io} from 'socket.io-client';
export const socket=io('http://localhost:5000',{autoConnect:false,auth:cb=>cb({token:localStorage.getItem('chat_token')})});
```

## External services and limitations
SMTP is needed for email OTP/reset. SMS OTP is not included. VAPID keys and browser subscriptions are needed for Web Push. Cloudinary credentials provide durable media. Configure STUN/TURN for calls; group calls require SFU infrastructure. This project is not end-to-end encrypted. In-memory revocation/presence require Redis/shared adapter for multiple instances. Review and integration-test before production.


## E2EE device keys
- `POST /api/e2ee/devices` — register public keys for this device (`deviceId`, `identityPublicKey`, `signedPreKeyPublic`, `signedPreKeySignature`, `oneTimePreKeys`). Never send private keys.
- `GET /api/e2ee/devices` — list this account's registered devices.
- `DELETE /api/e2ee/devices/:deviceId` — remove a device's public keys.
- `POST /api/e2ee/devices/prekeys` — append one-time public prekeys (`deviceId`, `oneTimePreKeys`).
- `GET /api/e2ee/users/:userId/bundles` — fetch public bundles; user must be self or share a conversation. A one-time prekey is consumed atomically when available.

When `E2EE_REQUIRED=true`, `POST /api/messages` requires `encryptedPayload` and rejects top-level plaintext text/attachments. `PATCH /api/messages/:id` also requires encrypted payload. Client-side search is required because the server cannot inspect ciphertext.

## Sessions
- `POST /api/auth/logout` revokes the current session across app instances.
- `POST /api/auth/logout-all` revokes every session for the account.
