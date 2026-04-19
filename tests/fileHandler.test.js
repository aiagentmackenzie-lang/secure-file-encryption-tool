const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');
const { writeEncryptedFile, readEncryptedFile } = require('../src/utils/fileHandler');

const TMP = path.join(__dirname, 'tmp_test.enc');
const mockPayload = {
  salt:      crypto.randomBytes(32),
  nonce:     crypto.randomBytes(12),
  encrypted: crypto.randomBytes(64),
  authTag:   crypto.randomBytes(16),
};

afterAll(() => {
  if (fs.existsSync(TMP)) fs.unlinkSync(TMP);
});

describe('SEFT — File Handler Tests', () => {
  test('write then read produces identical fields', () => {
    writeEncryptedFile(TMP, mockPayload);
    const parsed = readEncryptedFile(TMP);

    expect(parsed.salt.equals(mockPayload.salt)).toBe(true);
    expect(parsed.nonce.equals(mockPayload.nonce)).toBe(true);
    expect(parsed.encrypted.equals(mockPayload.encrypted)).toBe(true);
    expect(parsed.authTag.equals(mockPayload.authTag)).toBe(true);
  });

  test('file with wrong magic bytes is rejected', () => {
    const bad = Buffer.alloc(100, 0x00); // All zeros — no SEFT magic
    fs.writeFileSync(TMP, bad);
    expect(() => readEncryptedFile(TMP)).toThrow('magic');
  });

  test('file with unsupported version is rejected', () => {
    // Write a valid SEFT header but with version 0xFF
    const magic   = Buffer.from('SEFT');
    const version = Buffer.from([0xFF]);
    const rest    = crypto.randomBytes(80);
    fs.writeFileSync(TMP, Buffer.concat([magic, version, rest]));
    expect(() => readEncryptedFile(TMP)).toThrow('Unsupported file version');
  });
});
