import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createDeviceKeyMaterial,
  encryptMessage,
  decryptMessage,
  encryptFile,
  decryptFile,
  extractContentKey,
  createEnvelopeForDevice
} from '../client-examples/e2ee.js';

test('E2EE text round-trip encrypts ciphertext and decrypts only on recipient device', async () => {
  const recipient = await createDeviceKeyMaterial('test-recipient-device', 2);
  const bundle = {...recipient.publicRegistration, userId:'recipient', oneTimePreKey:recipient.publicRegistration.oneTimePreKeys[0]};
  const payload = await encryptMessage('private hello', 'test-sender-device', [bundle]);
  assert.notEqual(payload.ciphertext, 'private hello');
  assert.equal(await decryptMessage(payload, 'test-recipient-device', recipient.privateJwks), 'private hello');
});

test('E2EE media round-trip', async () => {
  const original = new Blob(['private media bytes'], {type:'text/plain'});
  const encrypted = await encryptFile(original);
  assert.notEqual(await encrypted.blob.text(), 'private media bytes');
  const clear = await decryptFile(await encrypted.blob.arrayBuffer(), encrypted.metadata);
  assert.equal(await clear.text(), 'private media bytes');
});

test('E2EE multi-device historical access: Device 2 cannot decrypt until Device 1 authorizes keys', async () => {
  const dev1 = await createDeviceKeyMaterial('device-1', 2);
  const dev2 = await createDeviceKeyMaterial('device-2', 2);

  const dev1Bundle = { ...dev1.publicRegistration, userId: 'userA', oneTimePreKey: dev1.publicRegistration.oneTimePreKeys[0] };
  const dev2Bundle = { ...dev2.publicRegistration, userId: 'userA', oneTimePreKey: dev2.publicRegistration.oneTimePreKeys[0] };

  // Message sent when only Device 1 existed
  const payload = await encryptMessage('historical secret for device 1', 'device-1', [dev1Bundle]);

  // 1. Device 1 can decrypt
  const clearOnDev1 = await decryptMessage(payload, 'device-1', dev1.privateJwks);
  assert.equal(clearOnDev1, 'historical secret for device 1');

  // 2. Device 2 CANNOT decrypt (throws "This message was not encrypted for this device")
  await assert.rejects(
    async () => { await decryptMessage(payload, 'device-2', dev2.privateJwks); },
    /not encrypted for this device/
  );

  // 3. User grants historical access: Device 1 extracts content key & creates envelope for Device 2
  const rawKey = await extractContentKey(payload, 'device-1', dev1.privateJwks);
  assert.equal(rawKey.length, 32); // 256-bit AES key

  const dev2Envelope = await createEnvelopeForDevice(rawKey, dev2Bundle);
  assert.equal(dev2Envelope.recipientDeviceId, 'device-2');

  // 4. Server receives envelope and updates message
  payload.recipientEnvelopes.push(dev2Envelope);

  // 5. Device 2 can now decrypt the historical message seamlessly!
  const clearOnDev2 = await decryptMessage(payload, 'device-2', dev2.privateJwks);
  assert.equal(clearOnDev2, 'historical secret for device 1');
});
