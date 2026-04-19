const crypto = require('crypto');
const { deriveKey } = require('../src/crypto/kdf');

describe('SEFT — Key Derivation Tests', () => {
  test('same password + salt always produces identical key (determinism)', async () => {
    const salt = crypto.randomBytes(32);
    const k1   = await deriveKey('TestPassword!123', salt);
    const k2   = await deriveKey('TestPassword!123', salt);
    expect(k1.equals(k2)).toBe(true);
  });

  test('different salts always produce different keys', async () => {
    const k1 = await deriveKey('TestPassword!123', crypto.randomBytes(32));
    const k2 = await deriveKey('TestPassword!123', crypto.randomBytes(32));
    expect(k1.equals(k2)).toBe(false);
  });

  test('output is exactly 32 bytes (256-bit AES key)', async () => {
    const key = await deriveKey('AnyPassword!', crypto.randomBytes(32));
    expect(key.length).toBe(32);
  });

  test('different passwords with same salt produce different keys', async () => {
    const salt = crypto.randomBytes(32);
    const k1   = await deriveKey('password_A!', salt);
    const k2   = await deriveKey('password_B!', salt);
    expect(k1.equals(k2)).toBe(false);
  });

  test('rejects non-Buffer salt', async () => {
    await expect(deriveKey('password!', 'not-a-buffer'))
      .rejects.toThrow(TypeError);
  });

  test('rejects empty password', async () => {
    await expect(deriveKey('', crypto.randomBytes(32)))
      .rejects.toThrow('non-empty string');
  });
});
