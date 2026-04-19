// src/crypto/decrypt.js
// AES-256-GCM authenticated decryption.
//
// SECURITY: All failures use the same generic error message to prevent
// timing attacks and information leakage.

const crypto = require("crypto");
const { deriveKey } = require("./kdf");

const DECRYPTION_ERROR = "Decryption failed: invalid password or corrupted data.";

function validateInputBuffers(salt, nonce, encrypted, authTag) {
  const validSalt = Buffer.isBuffer(salt) && salt.length > 0;
  const validNonce = Buffer.isBuffer(nonce) && nonce.length > 0;
  const validEncrypted = Buffer.isBuffer(encrypted) && encrypted.length > 0;
  const validAuthTag = Buffer.isBuffer(authTag) && authTag.length > 0;
  return validSalt && validNonce && validEncrypted && validAuthTag;
}

async function decryptFile(data, password) {
  const { salt, nonce, encrypted, authTag } = data;
  
  if (!validateInputBuffers(salt, nonce, encrypted, authTag)) {
    throw new Error(DECRYPTION_ERROR);
  }

  let key;
  try {
    key = await deriveKey(password, salt);
  } catch {
    throw new Error(DECRYPTION_ERROR);
  }

  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAuthTag(authTag);

    try {
      const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      return decrypted;
    } catch {
      throw new Error(DECRYPTION_ERROR);
    }
  } finally {
    if (key) {
      key.fill(0);
    }
  }
}

module.exports = { decryptFile };
