const { encryptFile } = require('../src/crypto/encrypt');
const { decryptFile } = require('../src/crypto/decrypt');

const PASSWORD  = 'TamperTest_Pass!99';
const PLAINTEXT = Buffer.from('Tamper detection test payload — do not modify.');

describe('SEFT — Tamper Detection Tests', () => {
  test('flipping one ciphertext bit causes auth failure', async () => {
    const payload = await encryptFile(PLAINTEXT, PASSWORD);
    const tampered = Buffer.from(payload.encrypted);
    tampered[0] ^= 0xFF; // XOR-flip all bits in the first byte
    await expect(decryptFile({ ...payload, encrypted: tampered }, PASSWORD))
      .rejects.toThrow('Decryption failed');
  });

  test('zeroed auth tag causes failure', async () => {
    const payload = await encryptFile(PLAINTEXT, PASSWORD);
    const badTag  = Buffer.alloc(16, 0x00);
    await expect(decryptFile({ ...payload, authTag: badTag }, PASSWORD))
      .rejects.toThrow('Decryption failed');
  });

  test('wrong nonce causes auth failure', async () => {
    const payload  = await encryptFile(PLAINTEXT, PASSWORD);
    const badNonce = Buffer.alloc(12, 0xAB);
    await expect(decryptFile({ ...payload, nonce: badNonce }, PASSWORD))
      .rejects.toThrow('Decryption failed');
  });

  test('truncated ciphertext causes auth failure', async () => {
    const payload   = await encryptFile(PLAINTEXT, PASSWORD);
    const truncated = payload.encrypted.slice(0, Math.floor(payload.encrypted.length / 2));
    await expect(decryptFile({ ...payload, encrypted: truncated }, PASSWORD))
      .rejects.toThrow('Decryption failed');
  });

  test('wrong salt produces wrong key → auth failure', async () => {
    const payload = await encryptFile(PLAINTEXT, PASSWORD);
    const badSalt = Buffer.alloc(32, 0xFF);
    await expect(decryptFile({ ...payload, salt: badSalt }, PASSWORD))
      .rejects.toThrow('Decryption failed');
  });
});
