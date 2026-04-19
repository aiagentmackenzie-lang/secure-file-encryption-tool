# 🔐 Secure File Encryption Tool (SEFT)

A production-grade command-line file encryption tool using **AES-256-GCM** authenticated encryption with **Argon2id** memory-hard key derivation.

## Features

- **AES-256-GCM** — NIST-approved authenticated encryption (confidentiality + integrity)
- **Argon2id** — OWASP-recommended memory-hard KDF (GPU/ASIC resistant)
- **Secure by default** — Passwords never appear in process lists or shell history
- **Tamper detection** — Any modification to encrypted files is detected and rejected
- **Zero key exposure** — Keys are wiped from memory immediately after use

## Installation

```bash
git clone https://github.com/yourname/secure-encryptor.git
cd secure-encryptor
npm install
```

Requires Node.js ≥ 18.0.0

## Usage

### Encrypt a file

```bash
node src/cli/index.js encrypt report.pdf
# or
npm run encrypt -- report.pdf
```

**Output:**
```
🔑 Enter password: 
⏳ Deriving key with Argon2id (this may take a moment)...
✅ Encrypted successfully → report.pdf.enc
```

### Decrypt a file

```bash
node src/cli/index.js decrypt report.pdf.enc
# or
npm run decrypt -- report.pdf.enc
```

**Output:**
```
🔑 Enter password: 
⏳ Deriving key with Argon2id (this may take a moment)...
✅ Decrypted successfully → report.pdf.dec
```

### Wrong password or tampered file

```
🔑 Enter password: 
⏳ Deriving key with Argon2id (this may take a moment)...
❌ Decryption failed: invalid password or corrupted data.
```

> Both wrong password AND file tampering produce the **same** generic error message — this removes information oracles that could aid attackers.

## Programmatic API

```javascript
const seft = require('./src');
const fs = require('fs');

// Encrypt
const buffer = fs.readFileSync('secret.pdf');
const payload = await seft.encryptFile(buffer, 'myStrongPassword!');
seft.writeEncryptedFile('secret.pdf.enc', payload);

// Decrypt
const parsed = seft.readEncryptedFile('secret.pdf.enc');
const plaintext = await seft.decryptFile(parsed, 'myStrongPassword!');
fs.writeFileSync('secret.pdf.dec', plaintext);
```

## Cryptographic Design

| Primitive | Choice | Purpose |
|-----------|--------|---------|
| Encryption | AES-256-GCM | Confidentiality + integrity |
| Key Derivation | Argon2id | Memory-hard password hashing |
| Salt | 32 bytes (random) | Unique key per file |
| Nonce | 12 bytes (random) | Unique IV per encryption |
| Auth Tag | 128-bit | Tamper detection |

**Argon2id Parameters (exceed OWASP minimums):**
- Memory: 64 MiB (OWASP min: 19 MiB)
- Time: 3 iterations (OWASP min: 2)
- Parallelism: 1

## Encrypted File Format

```
[MAGIC(4) | VERSION(1) | SALT(32) | NONCE(12) | CIPHERTEXT(N) | AUTHTAG(16)]
```

- **MAGIC:** "SEFT" — file type identifier
- **VERSION:** 0x01 — format version
- **SALT:** 256-bit random (Argon2id input)
- **NONCE:** 96-bit random (AES-GCM IV)
- **CIPHERTEXT:** Variable length encrypted data
- **AUTHTAG:** 128-bit GCM authentication tag

## Running Tests

```bash
npm test              # Run all tests with coverage
npm run test:watch    # Watch mode
```

**Test coverage:** 96.96% statements, 19 tests passing

## Security Considerations

### Protected Against
- Unauthorized file access (AES-256-GCM)
- Data tampering (GCM authentication tag)
- Offline brute-force attacks (Argon2id, 64 MiB memory cost)
- Password exposure via process arguments (TTY-only input)
- Key material persistence (secure memory zeroing)

### NOT Protected Against
- Keyloggers capturing password at input time
- OS-level memory dumps after key zeroing
- Weak or reused passwords (minimum 8 characters)
- Compromised host OS (root-level access)

## License

MIT

---

**Built for:** Cybersecurity Portfolio — Applied Cryptography
**Stack:** Node.js · AES-256-GCM · Argon2id
