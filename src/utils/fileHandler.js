// src/utils/fileHandler.js
// Handles the binary file format for SEFT-encrypted files.
//
// Format:
// [ MAGIC(4) | VERSION(1) | SALT(32) | NONCE(12) | CIPHERTEXT(N) | AUTHTAG(16) ]

const fs = require("fs");
const path = require("path");
const {
  MAGIC,
  VERSION,
  SALT_LENGTH,
  NONCE_LENGTH,
  AUTH_TAG_LENGTH,
} = require("./constants");

// Minimum file size: MAGIC + VERSION + SALT + NONCE + CIPHERTEXT(1) + AUTH_TAG
// Minimum file size: MAGIC + VERSION + SALT + NONCE + AUTH_TAG (no ciphertext required —
// the empty-ciphertext check below handles that case with a specific message)
const MIN_HEADER_SIZE = MAGIC.length + 1 + SALT_LENGTH + NONCE_LENGTH + AUTH_TAG_LENGTH;

/**
 * Validates that a buffer exists and has the expected length.
 * @param {Buffer} buf 
 * @param {number} expectedLength 
 * @param {string} name 
 * @throws {Error} if validation fails
 */
function validateBuffer(buf, expectedLength, name) {
  if (!Buffer.isBuffer(buf)) {
    throw new Error('Invalid file: ' + name + ' is not a buffer');
  }
  if (buf.length !== expectedLength) {
    throw new Error('Invalid file: ' + name + ' has wrong length (expected ' + expectedLength + ', got ' + buf.length + ')');
  }
}

/**
 * Writes a SEFT-format encrypted file to disk.
 * @param {string} outputPath - Destination file path (e.g. document.pdf.enc)
 * @param {{ salt, nonce, encrypted, authTag }} payload
 * @throws {Error} if payload fields are invalid
 */
function writeEncryptedFile(outputPath, payload) {
  const { salt, nonce, encrypted, authTag } = payload;
  
  // Validate all buffers before writing
  validateBuffer(salt, SALT_LENGTH, 'salt');
  validateBuffer(nonce, NONCE_LENGTH, 'nonce');
  validateBuffer(authTag, AUTH_TAG_LENGTH, 'authTag');
  if (!Buffer.isBuffer(encrypted) || encrypted.length === 0) {
    throw new Error('Invalid payload: encrypted must be a non-empty buffer');
  }

  const versionBuf = Buffer.alloc(1);
  versionBuf.writeUInt8(VERSION, 0);

  const file = Buffer.concat([
    MAGIC,
    versionBuf,
    salt,
    nonce,
    encrypted,
    authTag,
  ]);
  fs.writeFileSync(outputPath, file);
}

/**
 * Reads and parses a SEFT-format encrypted file from disk.
 * Validates magic bytes, version, buffer lengths, and file integrity.
 * @param {string} inputPath - Path to the .enc file
 * @returns {{ salt: Buffer, nonce: Buffer, encrypted: Buffer, authTag: Buffer }}
 * @throws {Error} if file is invalid, corrupted, or has wrong format
 */
function readEncryptedFile(inputPath) {
  // Security: Check for symlink attacks
  try {
    const stats = fs.lstatSync(inputPath);
    if (stats.isSymbolicLink()) {
      throw new Error('Invalid file: symlinks are not allowed for security reasons');
    }
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error('File not found: ' + inputPath);
    }
    throw err;
  }

  const file = fs.readFileSync(inputPath);
  
  // Check minimum file size
  if (file.length < MIN_HEADER_SIZE) {
    throw new Error('Invalid file: file is too small or corrupted (size: ' + file.length + ')');
  }
  
  let offset = 0;

  // Validate magic bytes
  const magic = file.slice(offset, offset + MAGIC.length);
  if (!magic.equals(MAGIC)) {
    throw new Error('Invalid file: not a SEFT-encrypted file (magic bytes mismatch)');
  }
  offset += MAGIC.length;

  // Validate version
  const version = file.readUInt8(offset);
  if (version !== VERSION) {
    throw new Error('Unsupported file version: 0x' + version.toString(16));
  }
  offset += 1;

  // Parse and validate salt
  const salt = file.slice(offset, offset + SALT_LENGTH);
  validateBuffer(salt, SALT_LENGTH, 'salt');
  offset += SALT_LENGTH;

  // Parse and validate nonce
  const nonce = file.slice(offset, offset + NONCE_LENGTH);
  validateBuffer(nonce, NONCE_LENGTH, 'nonce');
  offset += NONCE_LENGTH;

  // Auth tag is always the final AUTH_TAG_LENGTH bytes
  const authTag = file.slice(file.length - AUTH_TAG_LENGTH);
  validateBuffer(authTag, AUTH_TAG_LENGTH, 'authTag');

  // Ciphertext sits between nonce end and auth tag start
  const encrypted = file.slice(offset, file.length - AUTH_TAG_LENGTH);
  if (encrypted.length === 0) {
    throw new Error('Invalid file: ciphertext section is empty');
  }

  return { salt, nonce, encrypted, authTag };
}

module.exports = { writeEncryptedFile, readEncryptedFile, MIN_HEADER_SIZE };
