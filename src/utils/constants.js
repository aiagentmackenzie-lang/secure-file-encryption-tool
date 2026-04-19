// src/utils/constants.js
// Single source of truth for all cryptographic parameters.
// ⚠️ Changing any value here invalidates all previously encrypted files.
// Always increment VERSION when the file format changes.

module.exports = {
  MAGIC: Buffer.from('SEFT'),   // 4-byte file type identifier
  VERSION: 0x01,                 // Increment on file format changes
  SALT_LENGTH: 32,               // 256-bit salt — exceeds OWASP 16-byte minimum
  NONCE_LENGTH: 12,              // 96-bit AES-GCM standard nonce
  AUTH_TAG_LENGTH: 16,           // 128-bit GCM authentication tag (maximum possible)
  ARGON2_MEMORY: 65536,          // 64 MiB — exceeds OWASP minimum of 19 MiB
  ARGON2_TIME: 3,                // 3 iterations — exceeds OWASP minimum of 2
  ARGON2_PARALLELISM: 1,
  ARGON2_HASH_LENGTH: 32,        // 256-bit output = AES-256 key size
};
