const crypto = require('crypto');
const { encryptFile } = require('../src/crypto/encrypt');
const { decryptFile } = require('../src/crypto/decrypt');

const PASSWORD  = 'Integration_Test_Pass!99';
const PLAINTEXT = Buffer.from('This is a confidential test payload. SEFT v1.0');

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

describe('SEFT — Integration Tests', () => {
  test('encrypt → decrypt → hash match (round-trip integrity)', async () => {
    const payload   = await encryptFile(PLAINTEXT, PASSWORD);
    const recovered = await decryptFile(payload, PASSWORD);
    expect(sha256(recovered)).toBe(sha256(PLAINTEXT));
  });

  test('wrong password is rejected with generic error', async () => {
    const payload = await encryptFile(PLAINTEXT, PASSWORD);
    await expect(decryptFile(payload, 'wrong_password_123'))
      .rejects.toThrow('Decryption failed');
  });

  test('ciphertext does not contain plaintext bytes', async () => {
    const payload = await encryptFile(PLAINTEXT, PASSWORD);
    // The encrypted buffer should not contain the original plaintext substring
    expect(payload.encrypted.indexOf(PLAINTEXT)).toBe(-1);
  });

  test('two encryptions of same data produce unique outputs', async () => {
    const a = await encryptFile(PLAINTEXT, PASSWORD);
    const b = await encryptFile(PLAINTEXT, PASSWORD);
    // Salt, nonce, and ciphertext should ALL be different
    expect(a.salt.equals(b.salt)).toBe(false);
    expect(a.nonce.equals(b.nonce)).toBe(false);
    expect(a.encrypted.equals(b.encrypted)).toBe(false);
  });

  test('short password is rejected before encryption', async () => {
    await expect(encryptFile(PLAINTEXT, 'short'))
      .rejects.toThrow('Password must be at least 8 characters');
  });

  test('empty buffer is rejected', async () => {
    await expect(encryptFile(Buffer.alloc(0), PASSWORD))
      .rejects.toThrow('non-empty Buffer');
  });
});
