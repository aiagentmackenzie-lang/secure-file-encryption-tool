// src/crypto/encrypt.js
// AES-256-GCM authenticated encryption.
//
// GCM (Galois/Counter Mode) provides two guarantees simultaneously:
//   1. Confidentiality — AES-CTR encrypts the plaintext
//   2. Integrity      — GHASH produces a 128-bit authentication tag
//
// A fresh random salt and nonce are generated for EVERY encryption call,
// ensuring that two encryptions of the same file with the same password
// produce completely different ciphertext every time.

const crypto = require('crypto');
const { deriveKey } = require('./kdf');
const { SALT_LENGTH, NONCE_LENGTH } = require('../utils/constants');

/**
 * Encrypts a Buffer using AES-256-GCM with Argon2id key derivation.
 * @param {Buffer} buffer   - Plaintext file content to encrypt
 * @param {string} password - User-supplied password (minimum 8 characters)
 * @returns {Promise<{salt: Buffer, nonce: Buffer, encrypted: Buffer, authTag: Buffer}>}
 *
 * SECURITY: The derived key is zeroed in the `finally` block regardless of
 * whether encryption succeeds or fails.
 */
async function encryptFile(buffer, password) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    throw new Error('Input must be a non-empty Buffer');
  }
  if (typeof password !== 'string' || password.length < 8) {
    throw new Error('Password must be at least 8 characters');
  }

  const salt = crypto.randomBytes(SALT_LENGTH);    // Fresh 256-bit salt
  const nonce = crypto.randomBytes(NONCE_LENGTH);  // Fresh 96-bit IV
  const key = await deriveKey(password, salt);

  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
    const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
    const authTag = cipher.getAuthTag(); // Must be called AFTER cipher.final()

    return { salt, nonce, encrypted, authTag };
  } finally {
    key.fill(0); // 🔐 Zero key material from memory immediately after use
  }
}

module.exports = { encryptFile };
