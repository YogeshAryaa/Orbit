# Orbit — Real-Time Chat Backend v3 (E2EE + Redis scale-out)

Node.js 20+, Express, MongoDB/Mongoose, Socket.IO, Redis, JWT sessions, email OTP, Cloudinary, Web Push, and client-side Web Crypto encryption.

## Implemented in this version

- **End-to-end encrypted message payloads (E2EE enforced by default):** clients encrypt content with Web Crypto AES-256-GCM; a per-message content key is wrapped separately for every recipient device using ephemeral P-256 ECDH + HKDF-SHA-256. The server stores and relays ciphertext only and has no decryption keys.
- **Public device-key registry:** register identity signing public key, signed ECDH prekey, signature, and one-time public prekeys; fetch key bundles; replenish prekeys; remove a device's public keys.
- **Encrypted media path:** encrypt a file in the browser before uploading. In E2EE mode the upload endpoint accepts only `application/octet-stream` ciphertext; file name/type and decryption key/nonce should be included inside the encrypted message body, not the ordinary attachment fields.
- **Redis-backed shared sessions and revocation:** every JWT has a session ID; Redis stores active sessions with TTL. Logout revokes one session, `/api/auth/logout-all` revokes all sessions, and password reset revokes all sessions. Every REST request and Socket.IO handshake checks the shared session record.
- **Socket.IO Redis adapter:** broadcasts and room operations work across multiple Node instances when all instances use the same Redis URL and JWT secret.
- **Shared Redis rate limits:** API and authentication request counters use the shared Redis store, avoiding per-replica rate-limit resets.
- Existing account, user search, conversations/groups, encrypted messages, reactions, receipts, uploads, WebRTC signaling, email OTP/reset, Web Push, blocking and moderation APIs.

## Run locally

1. Install Node.js 20+ and Redis (or use a managed Redis service). For local Redis, run `docker compose -f docker-compose.redis.yml up -d`.
2. Copy `.env.example` to `.env` and set `MONGODB_URI`, a random `JWT_SECRET` of at least 32 characters, `REDIS_URL`, and `CLIENT_ORIGIN`.
3. `npm install`
4. `npm run check`
5. `npm test`
6. `npm run dev`
7. `GET http://localhost:5000/api/health`

For production, `REDIS_URL` is mandatory; the server exits rather than silently starting a non-shared session store. All API instances must share the same Redis and JWT secret. Put the service behind HTTPS, configure MongoDB/Redis private networking and ACLs, and run multiple stateless app replicas behind a load balancer with WebSocket support. If polling transport remains enabled, configure load-balancer sticky sessions; alternatively configure clients to use WebSocket transport only if your environment supports it reliably.

## E2EE client integration

See `client-examples/e2ee.js` for browser Web Crypto helpers:

1. On first install, call `createDeviceKeyMaterial()` in the browser. Persist `privateJwks` locally using IndexedDB/OS secure storage; do not send it to the server or store it in ordinary app logs. POST only `publicRegistration` to `/api/e2ee/devices`.
2. Fetch `/api/e2ee/users/:userId/bundles` for each recipient. The server atomically consumes one one-time prekey when available. Verify the signed prekey before encryption (the helper does this).
3. Include the sender's other device bundles as recipients to enable multi-device sync.
4. Use `encryptMessage(JSON.stringify({text, attachments:[...]}), senderDeviceId, bundles)` and POST its result as `encryptedPayload` to `/api/messages`. In E2EE mode, do not send plaintext `text` or top-level `attachments` fields.
5. Decrypt returned `encryptedPayload` with `decryptMessage(payload, currentDeviceId, privateJwks)` on the client. Search decrypted local messages on the client; server-side text search is intentionally disabled while E2EE is required.
6. For media, call `encryptFile(file)`, upload its ciphertext `blob` as multipart field `file`, then put the returned URL plus the helper's key/nonce/name/type metadata inside the encrypted JSON content. Download the ciphertext URL and use `decryptFile` client-side.
7. Replenish one-time prekeys with `POST /api/e2ee/devices/prekeys` before the device runs low. The server stores only public keys.

### E2EE scope and honest security boundary

This is a practical browser E2EE baseline, **not a drop-in implementation of the Signal Protocol**. AES-GCM provides authenticated encryption and the server cannot decrypt message bodies or encrypted media. However, this baseline does not implement the Signal Double Ratchet, robust asynchronous session establishment, key transparency, safety-number verification, or strong forward secrecy after a recipient device's long-term signed-prekey private key is compromised. For high-risk/large-scale production, replace the key agreement layer with an audited Signal Protocol implementation and conduct an independent security review. A malicious server could also substitute public keys because transparency/pinning is not implemented. Users should verify identity fingerprints out-of-band if threat model requires it.

## Redis and multi-server operation

- `REDIS_URL` points at a shared Redis deployment; TLS URLs are recommended for managed services.
- `SESSION_PREFIX` namespaces session keys.
- Redis holds only session metadata and Socket.IO pub/sub, not plaintext messages or encryption private keys.
- `POST /api/auth/logout` revokes the current token/session across every instance; `POST /api/auth/logout-all` revokes every session for the account.
- Use Redis ACLs, private network access, TLS, persistence/HA, alerts, and backups appropriate to your environment. Redis failure causes auth/session operations to fail rather than bypass revocation.

## Important deployment notes

- Set `E2EE_REQUIRED=true` (default). `E2EE_REQUIRED=false` is a deliberate legacy plaintext compatibility mode and should not be used for new deployments.
- The app must use HTTPS; browser Web Crypto requires a secure context except localhost.
- Email verification/password reset require SMTP. SMS OTP is not implemented because no provider was specified.
- Cloudinary is required by this multi-instance build in production so encrypted uploads are shared; local upload storage is development-only. In E2EE mode the uploaded bytes must already be encrypted by the client.
- Web Push notifications are generic and never contain message plaintext.
- WebRTC signaling relays direct and group call setup; group calls use a peer-to-peer mesh, while an SFU is recommended for larger groups. Media encryption is provided by WebRTC's DTLS-SRTP, not by this E2EE message helper.
- Run integration tests with dedicated MongoDB and Redis instances before production. This ZIP has syntax and unit tests but cannot verify your cloud credentials or deployment configuration.
