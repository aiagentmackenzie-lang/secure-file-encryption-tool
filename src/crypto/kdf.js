// src/crypto/kdf.js
// Argon2id key derivation module.
//
// Argon2id is the OWASP-recommended and PHC-winning KDF for password-based
// encryption. It is resistant to GPU and ASIC attacks due to its memory-hard
// design — an attacker cannot parallelize brute-force attempts cheaply.
//
// SECURITY NOTE: The returned Buffer MUST be zeroed by the caller with
// key.fill(0) immediately after use. Never log, store, or transmit it.

const argon2 = require('argon2');
const {
  ARGON2_MEMORY,
  ARGON2_TIME,
  ARGON2_PARALLELISM,
  ARGON2_HASH_LENGTH,
} = require('../utils/constants');

/**
 * Derives a cryptographic key from a password and salt using Argon2id.
 * @param {string} password - The user-supplied password
 * @param {Buffer} salt     - Cryptographically random salt (SALT_LENGTH bytes)
 * @returns {Promise<Buffer>} - Raw 32-byte key material
 */
async function deriveKey(password, salt) {
  if (!Buffer.isBuffer(salt)) {
    throw new TypeError('Salt must be a Buffer');
  }
  if (typeof password !== 'string' || password.length === 0) {
    throw new TypeError('Password must be a non-empty string');
  }
  return await argon2.hash(password, {
    type: argon2.argon2id,
    salt,
    hashLength: ARGON2_HASH_LENGTH,
    timeCost: ARGON2_TIME,
    memoryCost: ARGON2_MEMORY,
    parallelism: ARGON2_PARALLELISM,
    raw: true, // Return raw bytes, not the encoded Argon2 string
  });
}

module.exports = { deriveKey };
