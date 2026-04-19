const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { writeEncryptedFile, readEncryptedFile } = require('../src/utils/fileHandler');
const { encryptFile } = require('../src/crypto/encrypt');
const { decryptFile } = require('../src/crypto/decrypt');

const TMP = path.join(__dirname, 'tmp_edge.enc');

afterAll(() => {
  if (fs.existsSync(TMP)) fs.unlinkSync(TMP);
});

describe('SEFT — File Handler Edge Cases', () => {
  test('writeEncryptedFile rejects wrong salt length', () => {
    const badPayload = {
      salt: crypto.randomBytes(16), // Wrong: should be 32
      nonce: crypto.randomBytes(12),
      encrypted: crypto.randomBytes(64),
      authTag: crypto.randomBytes(16),
    };
    expect(() => writeEncryptedFile(TMP, badPayload)).toThrow('salt has wrong length');
  });

  test('writeEncryptedFile rejects wrong nonce length', () => {
    const badPayload = {
      salt: crypto.randomBytes(32),
      nonce: crypto.randomBytes(8), // Wrong: should be 12
      encrypted: crypto.randomBytes(64),
      authTag: crypto.randomBytes(16),
    };
    expect(() => writeEncryptedFile(TMP, badPayload)).toThrow('nonce has wrong length');
  });

  test('writeEncryptedFile rejects wrong authTag length', () => {
    const badPayload = {
      salt: crypto.randomBytes(32),
      nonce: crypto.randomBytes(12),
      encrypted: crypto.randomBytes(64),
      authTag: crypto.randomBytes(8), // Wrong: should be 16
    };
    expect(() => writeEncryptedFile(TMP, badPayload)).toThrow('authTag has wrong length');
  });

  test('writeEncryptedFile rejects empty encrypted buffer', () => {
    const badPayload = {
      salt: crypto.randomBytes(32),
      nonce: crypto.randomBytes(12),
      encrypted: Buffer.alloc(0),
      authTag: crypto.randomBytes(16),
    };
    expect(() => writeEncryptedFile(TMP, badPayload)).toThrow('non-empty buffer');
  });

  test('writeEncryptedFile rejects non-Buffer salt', () => {
    const badPayload = {
      salt: 'not a buffer',
      nonce: crypto.randomBytes(12),
      encrypted: crypto.randomBytes(64),
      authTag: crypto.randomBytes(16),
    };
    expect(() => writeEncryptedFile(TMP, badPayload)).toThrow('not a buffer');
  });

  test('readEncryptedFile rejects file too small', () => {
    fs.writeFileSync(TMP, Buffer.alloc(10, 0x00));
    expect(() => readEncryptedFile(TMP)).toThrow('too small or corrupted');
  });

  test('readEncryptedFile rejects empty ciphertext (header-only file)', () => {
    // Build a file with exactly the header size (no ciphertext)
    const magic = Buffer.from('SEFT');
    const version = Buffer.from([0x01]);
    const salt = crypto.randomBytes(32);
    const nonce = crypto.randomBytes(12);
    const authTag = crypto.randomBytes(16);
    // No encrypted section!
    const file = Buffer.concat([magic, version, salt, nonce, authTag]);
    fs.writeFileSync(TMP, file);
    expect(() => readEncryptedFile(TMP)).toThrow('ciphertext section is empty');
  });

  test('readEncryptedFile rejects symlink', () => {
    const linkPath = path.join(__dirname, 'tmp_symlink.enc');
    try {
      fs.symlinkSync(TMP, linkPath);
      // Create a valid file first
      const payload = {
        salt: crypto.randomBytes(32),
        nonce: crypto.randomBytes(12),
        encrypted: crypto.randomBytes(64),
        authTag: crypto.randomBytes(16),
      };
      writeEncryptedFile(TMP, payload);
      expect(() => readEncryptedFile(linkPath)).toThrow('symlinks');
    } finally {
      if (fs.existsSync(linkPath)) fs.unlinkSync(linkPath);
    }
  });
});

describe('SEFT — Decrypt Edge Cases', () => {
  test('decryptFile rejects non-Buffer salt', async () => {
    await expect(decryptFile({
      salt: 'not-a-buffer',
      nonce: crypto.randomBytes(12),
      encrypted: crypto.randomBytes(64),
      authTag: crypto.randomBytes(16),
    }, 'password123')).rejects.toThrow('Decryption failed');
  });

  test('decryptFile rejects empty encrypted buffer', async () => {
    await expect(decryptFile({
      salt: crypto.randomBytes(32),
      nonce: crypto.randomBytes(12),
      encrypted: Buffer.alloc(0),
      authTag: crypto.randomBytes(16),
    }, 'password123')).rejects.toThrow('Decryption failed');
  });

  test('decryptFile handles KDF failure gracefully', async () => {
    // Pass valid-looking buffers but a non-string password to trigger KDF TypeError
    await expect(decryptFile({
      salt: crypto.randomBytes(32),
      nonce: crypto.randomBytes(12),
      encrypted: crypto.randomBytes(64),
      authTag: crypto.randomBytes(16),
    }, 12345)).rejects.toThrow('Decryption failed');
  });
});