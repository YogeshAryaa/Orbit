// Browser-side E2EE helper. Private JWKs MUST stay on the device (prefer IndexedDB/WebCrypto non-extractable keys).
// Wire this helper into your React client; the API server never receives plaintext or private keys.
const enc = new TextEncoder();
const dec = new TextDecoder();
const toB64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const fromB64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const packJwk = (jwk) => toB64(enc.encode(JSON.stringify(jwk)));
const unpackJwk = (value) => JSON.parse(dec.decode(fromB64(value)));
const randomId = () => crypto.randomUUID();

async function exportPublic(key) { return packJwk(await crypto.subtle.exportKey('jwk', key)); }
async function importEcdhPublic(value) {
  return crypto.subtle.importKey('jwk', unpackJwk(value), {name:'ECDH', namedCurve:'P-256'}, true, []);
}
async function importEcdsaPublic(value) {
  return crypto.subtle.importKey('jwk', unpackJwk(value), {name:'ECDSA', namedCurve:'P-256'}, true, ['verify']);
}
async function deriveWrappingKey(privateKey, publicKey, salt) {
  const shared = await crypto.subtle.deriveBits({name:'ECDH', public:publicKey}, privateKey, 256);
  const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'HKDF', hash:'SHA-256', salt, info:enc.encode('chat-e2ee-v1-content-key-wrap')}, material, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}

// Create once per device. Store privateJwks securely on the client, never in the API/database.
export async function createDeviceKeyMaterial(deviceId = randomId(), prekeyCount = 30) {
  const identity = await crypto.subtle.generateKey({name:'ECDSA', namedCurve:'P-256'}, true, ['sign','verify']);
  const signedPreKey = await crypto.subtle.generateKey({name:'ECDH', namedCurve:'P-256'}, true, ['deriveBits']);
  const signedPreKeyPublic = await exportPublic(signedPreKey.publicKey);
  const signature = await crypto.subtle.sign({name:'ECDSA', hash:'SHA-256'}, identity.privateKey, enc.encode(signedPreKeyPublic));
  const oneTimePreKeys = [];
  const privateOneTimePreKeys = {};
  for (let i=0; i<prekeyCount; i++) {
    const pair = await crypto.subtle.generateKey({name:'ECDH', namedCurve:'P-256'}, true, ['deriveBits']);
    const keyId = randomId();
    oneTimePreKeys.push({keyId, publicKey:await exportPublic(pair.publicKey)});
    privateOneTimePreKeys[keyId] = await crypto.subtle.exportKey('jwk', pair.privateKey);
  }
  return {
    publicRegistration: {
      deviceId,
      identityPublicKey: await exportPublic(identity.publicKey),
      signedPreKeyPublic,
      signedPreKeySignature: toB64(signature),
      oneTimePreKeys
    },
    privateJwks: {
      identityPrivateKey: await crypto.subtle.exportKey('jwk', identity.privateKey),
      signedPreKeyPrivateKey: await crypto.subtle.exportKey('jwk', signedPreKey.privateKey),
      oneTimePreKeys: privateOneTimePreKeys
    }
  };
}

export async function verifyBundleSignature(bundle) {
  const identity = await importEcdsaPublic(bundle.identityPublicKey);
  return crypto.subtle.verify({name:'ECDSA', hash:'SHA-256'}, identity, fromB64(bundle.signedPreKeySignature), enc.encode(bundle.signedPreKeyPublic));
}

// bundles must include every recipient device and the sender's other devices for multi-device sync.
// The content is encrypted once; a separate wrapped content key is produced for each device.
export async function encryptMessage(plaintext, senderDeviceId, bundles) {
  if (!Array.isArray(bundles) || bundles.length === 0) throw new Error('No recipient device key bundles supplied');
  for (const bundle of bundles) if (!(await verifyBundleSignature(bundle))) throw new Error(`Invalid signed prekey signature for device ${bundle.deviceId}`);
  const contentKey = await crypto.subtle.generateKey({name:'AES-GCM', length:256}, true, ['encrypt','decrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({name:'AES-GCM', iv:nonce}, contentKey, enc.encode(plaintext));
  const rawContentKey = await crypto.subtle.exportKey('raw', contentKey);
  const recipientEnvelopes = [];
  for (const bundle of bundles) {
    const oneTime = bundle.oneTimePreKey;
    const recipientPublic = await importEcdhPublic(oneTime?.publicKey || bundle.signedPreKeyPublic);
    const ephemeral = await crypto.subtle.generateKey({name:'ECDH', namedCurve:'P-256'}, true, ['deriveBits']);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const wrapKey = await deriveWrappingKey(ephemeral.privateKey, recipientPublic, salt);
    const keyNonce = crypto.getRandomValues(new Uint8Array(12));
    const encryptedKey = await crypto.subtle.encrypt({name:'AES-GCM', iv:keyNonce}, wrapKey, rawContentKey);
    recipientEnvelopes.push({
      recipientDeviceId: bundle.deviceId,
      oneTimePreKeyId: oneTime?.keyId || null,
      ephemeralPublicKey: await exportPublic(ephemeral.publicKey),
      salt: toB64(salt), keyNonce: toB64(keyNonce), encryptedKey: toB64(encryptedKey)
    });
  }
  return {version:1, algorithm:'ECDH-P256-HKDF-SHA256-AES256GCM', nonce:toB64(nonce), ciphertext:toB64(ciphertext), senderDeviceId, recipientEnvelopes};
}

// privateJwks is the locally stored private material for this device. Remove one-time private keys after successful decryption.
export async function decryptMessage(payload, deviceId, privateJwks) {
  if (payload?.version !== 1 || payload?.algorithm !== 'ECDH-P256-HKDF-SHA256-AES256GCM') throw new Error('Unsupported encrypted message format');
  const envelope = payload.recipientEnvelopes.find(e => e.recipientDeviceId === deviceId);
  if (!envelope) throw new Error('This message was not encrypted for this device');
  const useOneTime = envelope.oneTimePreKeyId && privateJwks.oneTimePreKeys?.[envelope.oneTimePreKeyId];
  const privateJwk = useOneTime ? privateJwks.oneTimePreKeys[envelope.oneTimePreKeyId] : privateJwks.signedPreKeyPrivateKey;
  if (!privateJwk) throw new Error('Required private key is unavailable on this device');
  const privateKey = await crypto.subtle.importKey('jwk', privateJwk, {name:'ECDH', namedCurve:'P-256'}, false, ['deriveBits']);
  const ephemeralPublic = await importEcdhPublic(envelope.ephemeralPublicKey);
  const wrapKey = await deriveWrappingKey(privateKey, ephemeralPublic, fromB64(envelope.salt));
  const rawContentKey = await crypto.subtle.decrypt({name:'AES-GCM', iv:fromB64(envelope.keyNonce)}, wrapKey, fromB64(envelope.encryptedKey));
  const contentKey = await crypto.subtle.importKey('raw', rawContentKey, {name:'AES-GCM'}, false, ['decrypt']);
  const clear = await crypto.subtle.decrypt({name:'AES-GCM', iv:fromB64(payload.nonce)}, contentKey, fromB64(payload.ciphertext));
  if (useOneTime) {
    if (!privateJwks.consumedOneTimePreKeys) privateJwks.consumedOneTimePreKeys = {};
    privateJwks.consumedOneTimePreKeys[envelope.oneTimePreKeyId] = privateJwks.oneTimePreKeys[envelope.oneTimePreKeyId];
    delete privateJwks.oneTimePreKeys[envelope.oneTimePreKeyId];
  }
  return dec.decode(clear);
}


// Encrypt media before POST /api/uploads. Store key+nonce ONLY inside the encrypted message body.
export async function encryptFile(file) {
  const key = await crypto.subtle.generateKey({name:'AES-GCM', length:256}, true, ['encrypt','decrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const clear = await file.arrayBuffer();
  const encrypted = await crypto.subtle.encrypt({name:'AES-GCM', iv:nonce}, key, clear);
  return {
    blob: new Blob([encrypted], {type:'application/octet-stream'}),
    metadata: {name:file.name, mimeType:file.type || 'application/octet-stream', size:file.size, key:toB64(await crypto.subtle.exportKey('raw',key)), nonce:toB64(nonce)}
  };
}
export async function decryptFile(encryptedArrayBuffer, metadata) {
  const key = await crypto.subtle.importKey('raw', fromB64(metadata.key), {name:'AES-GCM'}, false, ['decrypt']);
  const clear = await crypto.subtle.decrypt({name:'AES-GCM', iv:fromB64(metadata.nonce)}, key, encryptedArrayBuffer);
  return new Blob([clear], {type:metadata.mimeType || 'application/octet-stream'});
}

export async function extractContentKey(payload, deviceId, privateJwks) {
  if (payload?.version !== 1 || payload?.algorithm !== 'ECDH-P256-HKDF-SHA256-AES256GCM') {
    throw new Error('Unsupported encrypted message format');
  }
  const envelope = payload.recipientEnvelopes?.find(e => e.recipientDeviceId === deviceId);
  if (!envelope) throw new Error('This message was not encrypted for this device');
  const useOneTime = envelope.oneTimePreKeyId && (privateJwks.oneTimePreKeys?.[envelope.oneTimePreKeyId] || privateJwks.consumedOneTimePreKeys?.[envelope.oneTimePreKeyId]);
  const privateJwk = useOneTime ? (privateJwks.oneTimePreKeys?.[envelope.oneTimePreKeyId] || privateJwks.consumedOneTimePreKeys?.[envelope.oneTimePreKeyId]) : privateJwks.signedPreKeyPrivateKey;
  if (!privateJwk) throw new Error('Required private key is unavailable on this device');

  const privateKey = await crypto.subtle.importKey('jwk', privateJwk, {name:'ECDH', namedCurve:'P-256'}, false, ['deriveBits']);
  const ephemeralPublic = await importEcdhPublic(envelope.ephemeralPublicKey);
  const wrapKey = await deriveWrappingKey(privateKey, ephemeralPublic, fromB64(envelope.salt));
  const rawContentKey = await crypto.subtle.decrypt({name:'AES-GCM', iv:fromB64(envelope.keyNonce)}, wrapKey, fromB64(envelope.encryptedKey));
  return new Uint8Array(rawContentKey);
}

export async function createEnvelopeForDevice(rawContentKey, targetBundle) {
  const oneTime = targetBundle.oneTimePreKey;
  const recipientPublic = await importEcdhPublic(oneTime?.publicKey || targetBundle.signedPreKeyPublic);
  const ephemeral = await crypto.subtle.generateKey({name:'ECDH', namedCurve:'P-256'}, true, ['deriveBits']);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const wrap = await deriveWrappingKey(ephemeral.privateKey, recipientPublic, salt);
  const keyNonce = crypto.getRandomValues(new Uint8Array(12));
  const rawBytes = rawContentKey instanceof Uint8Array ? rawContentKey : new Uint8Array(rawContentKey);
  const encryptedKey = await crypto.subtle.encrypt({name:'AES-GCM', iv:keyNonce}, wrap, rawBytes);
  return {
    recipientDeviceId: targetBundle.deviceId,
    oneTimePreKeyId: oneTime?.keyId || null,
    ephemeralPublicKey: await exportPublic(ephemeral.publicKey),
    salt: toB64(salt),
    keyNonce: toB64(keyNonce),
    encryptedKey: toB64(encryptedKey)
  };
}
