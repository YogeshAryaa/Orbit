import test from 'node:test';
import assert from 'node:assert/strict';
import { createDeviceKeyMaterial, encryptMessage, decryptMessage, encryptFile, decryptFile } from '../client-examples/e2ee.js';

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
