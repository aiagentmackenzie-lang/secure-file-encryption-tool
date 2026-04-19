// src/index.js
// Exports SEFT as a Node.js library for programmatic / embedded use.
// Allows other applications to integrate SEFT encryption without the CLI layer.

const { encryptFile } = require('./crypto/encrypt');
const { decryptFile } = require('./crypto/decrypt');
const { writeEncryptedFile, readEncryptedFile } = require('./utils/fileHandler');

module.exports = {
  encryptFile,
  decryptFile,
  writeEncryptedFile,
  readEncryptedFile,
};

/*
 * Programmatic Usage Example:
 *
 * const seft = require('./src');
 * const fs   = require('fs');
 *
 * // Encrypt
 * const buffer  = fs.readFileSync('secret.pdf');
 * const payload = await seft.encryptFile(buffer, 'myStrongPassword!');
 * seft.writeEncryptedFile('secret.pdf.enc', payload);
 *
 * // Decrypt
 * const parsed    = seft.readEncryptedFile('secret.pdf.enc');
 * const plaintext = await seft.decryptFile(parsed, 'myStrongPassword!');
 * fs.writeFileSync('secret.pdf.dec', plaintext);
 */
