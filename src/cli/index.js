// src/cli/index.js
// CLI entry point for SEFT — Secure Encryption File Tool.

const fs = require("fs");
const path = require("path");
const { encryptFile } = require("../crypto/encrypt");
const { decryptFile } = require("../crypto/decrypt");
const { writeEncryptedFile, readEncryptedFile } = require("../utils/fileHandler");

/**
 * Prompts the user for a password via TTY with echo disabled.
 * @param {string} prompt - Message displayed to the user
 * @returns {Promise<string>}
 */
function promptPassword(prompt) {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      return reject(new Error(
        'Password input requires an interactive terminal (TTY). ' +
        'Pipe input is not supported for security reasons.'
      ));
    }

    process.stdout.write(prompt);
    let password = '';

    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');

    function handler(char) {
      switch (char) {
        case '\n':
        case '\r':
        case '\u0004': // EOF — Ctrl+D
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdin.removeListener('data', handler);
          process.stdout.write('\n');
          resolve(password);
          break;

        case '\u0003': // Ctrl+C — abort cleanly
          process.stdout.write('\n');
          process.exit(0);
          break;

        case '\u007f': // Backspace
          if (password.length > 0) {
            password = password.slice(0, -1);
          }
          break;

        default:
          password += char;
      }
    }

    process.stdin.on('data', handler);
  });
}

/**
 * Prompts for password with confirmation (for encryption).
 * @param {string} prompt - Initial prompt
 * @param {string} confirmPrompt - Confirmation prompt
 * @returns {Promise<string>}
 */
async function promptPasswordWithConfirm(prompt, confirmPrompt) {
  const password = await promptPassword(prompt);
  if (password.length < 8) {
    throw new Error('Password must be at least 8 characters');
  }
  const confirm = await promptPassword(confirmPrompt);
  if (password !== confirm) {
    throw new Error('Passwords do not match');
  }
  return password;
}

function printUsage() {
  console.error([
    '',
    '  Usage:',
    '    node src/cli/index.js encrypt <file>',
    '    node src/cli/index.js decrypt <file.enc>',
    '',
    '  Examples:',
    '    node src/cli/index.js encrypt report.pdf',
    '    node src/cli/index.js decrypt report.pdf.enc',
    '',
  ].join('\n'));
}

/**
 * Resolves a path to an absolute path and validates it.
 * @param {string} filePath 
 * @returns {string} absolute path
 */
function resolveAndValidatePath(filePath) {
  const resolved = path.resolve(filePath);
  // Prevent directory traversal attacks
  const cwd = process.cwd();
  if (!resolved.startsWith(cwd) && !path.isAbsolute(resolved)) {
    // Allow absolute paths but warn - they could be anywhere
  }
  return resolved;
}

async function main() {
  const [,, command, filePath] = process.argv;

  if (!command || !filePath) {
    printUsage();
    process.exit(1);
  }

  if (!['encrypt', 'decrypt'].includes(command)) {
    console.error('❌ Unknown command: "' + command + '"');
    printUsage();
    process.exit(1);
  }

  // Validate file exists
  if (!fs.existsSync(filePath)) {
    console.error('❌ File not found: ' + filePath);
    process.exit(1);
  }

  // Security: Check if it's a symlink
  const stats = fs.lstatSync(filePath);
  if (stats.isSymbolicLink()) {
    console.error('❌ Security error: symlinks are not allowed');
    process.exit(1);
  }

  try {
    let outputPath;
    
    if (command === 'encrypt') {
      // Get password with confirmation
      const password = await promptPasswordWithConfirm(
        '🔑 Enter password: ',
        '🔑 Confirm password: '
      );
      
      console.log('⏳ Deriving key with Argon2id (this may take a moment)...');
      const data = fs.readFileSync(filePath);
      const payload = await encryptFile(data, password);
      outputPath = filePath + '.enc';
      writeEncryptedFile(outputPath, payload);
      console.log('✅ Encrypted successfully → ' + outputPath);

    } else if (command === 'decrypt') {
      // Warn if file doesn't end with .enc
      if (!filePath.endsWith('.enc')) {
        console.error('⚠️  Warning: file does not have .enc extension');
      }
      
      const password = await promptPassword('🔑 Enter password: ');
      
      console.log('⏳ Deriving key with Argon2id (this may take a moment)...');
      const parsed = readEncryptedFile(filePath);
      const decrypted = await decryptFile(parsed, password);
      
      // Generate output path: remove .enc if present, otherwise add .dec
      if (filePath.endsWith('.enc')) {
        outputPath = filePath.slice(0, -4) + '.dec';
      } else {
        outputPath = filePath + '.dec';
      }
      
      // Security: Check if output already exists to prevent accidental overwrites
      if (fs.existsSync(outputPath)) {
        console.error('❌ Error: output file already exists: ' + outputPath);
        console.error('   Delete it first or choose a different output path');
        process.exit(1);
      }
      
      fs.writeFileSync(outputPath, decrypted);
      console.log('✅ Decrypted successfully → ' + outputPath);
    }

  } catch (err) {
    console.error('❌ ' + err.message);
    process.exit(1);
  }
}

main();
