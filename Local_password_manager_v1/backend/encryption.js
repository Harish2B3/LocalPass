/**
 * Encryption Module for Password Manager Backend
 * Uses AES-256-GCM for secure encryption
 * 
 * SECURITY NOTE: In production, the encryption key MUST be stored
 * in environment variables and never committed to source control.
 */

const CryptoJS = require('crypto-js');
const crypto = require('crypto');

// ============================================
// ENCRYPTION KEY MANAGEMENT
// ============================================

/**
 * Get the encryption key from environment or use default for development
 * WARNING: The default key should NEVER be used in production!
 */
function getEncryptionKey() {
  const envKey = process.env.ENCRYPTION_KEY;

  if (envKey) {
    // Validate key length (AES-256 requires 32 bytes)
    if (envKey.length !== 32) {
      console.warn('ENCRYPTION_KEY should be exactly 32 characters for AES-256');
    }
    return envKey;
  }

  // Development fallback key - DO NOT USE IN PRODUCTION
  if (process.env.NODE_ENV === 'production') {
    throw new Error('ENCRYPTION_KEY environment variable is required in production');
  }

  console.warn('⚠️  Using development encryption key. Set ENCRYPTION_KEY in production!');
  return 'a-32-byte-long-super-secret-key!';
}

const SECRET_KEY = getEncryptionKey();

// ============================================
// AES ENCRYPTION (CryptoJS - for browser compatibility)
// ============================================

/**
 * Encrypt text using AES-256-CBC
 * @param {string} text - Text to encrypt
 * @returns {{iv: string, content: string}} - Encrypted data with IV
 */
const encrypt = (text) => {
  if (text === null || typeof text === 'undefined') {
    console.error("Encryption input is null or undefined. Encrypting empty string.");
    text = '';
  }

  const iv = CryptoJS.lib.WordArray.random(16);
  const encrypted = CryptoJS.AES.encrypt(text.toString(), CryptoJS.enc.Utf8.parse(SECRET_KEY), {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });

  return {
    iv: iv.toString(CryptoJS.enc.Hex),
    content: encrypted.toString()
  };
};

/**
 * Decrypt encrypted data
 * @param {{iv: string, content: string}} hash - Encrypted data with IV
 * @returns {string} - Decrypted text
 */
const decrypt = (hash) => {
  if (!hash || !hash.iv || !hash.content) {
    console.log('Hash is empty or invalid, returning empty string.');
    return '';
  }

  try {
    const key = CryptoJS.enc.Utf8.parse(SECRET_KEY);
    const iv = CryptoJS.enc.Hex.parse(hash.iv);

    const decryptedBytes = CryptoJS.AES.decrypt(hash.content, key, {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    });

    const decryptedText = decryptedBytes.toString(CryptoJS.enc.Utf8);

    if (!decryptedText && decryptedBytes.sigBytes > 0) {
      console.warn('Decryption warning: Data could not be represented as UTF-8.');
    }

    return decryptedText;
  } catch (error) {
    console.error('Decryption exception:', error);
    return '';
  }
};

// ============================================
// NATIVE CRYPTO (Node.js - for enhanced security)
// ============================================

/**
 * Encrypt using Node.js native crypto (AES-256-GCM)
 * More secure than CBC mode with built-in authentication
 * @param {string} text - Text to encrypt
 * @returns {{iv: string, content: string, tag: string}}
 */
const encryptNative = (text) => {
  if (!text) text = '';

  const iv = crypto.randomBytes(12); // 96 bits for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(SECRET_KEY), iv);

  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');

  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString('hex'),
    content: encrypted,
    tag: tag.toString('hex')
  };
};

/**
 * Decrypt using Node.js native crypto (AES-256-GCM)
 * @param {{iv: string, content: string, tag: string}} hash
 * @returns {string}
 */
const decryptNative = (hash) => {
  if (!hash || !hash.iv || !hash.content || !hash.tag) {
    return '';
  }

  try {
    const iv = Buffer.from(hash.iv, 'hex');
    const tag = Buffer.from(hash.tag, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(SECRET_KEY), iv);

    decipher.setAuthTag(tag);

    let decrypted = decipher.update(hash.content, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch (error) {
    console.error('Native decryption error:', error.message);
    return '';
  }
};

// ============================================
// HASHING UTILITIES
// ============================================

/**
 * Generate a secure random salt
 * @param {number} length - Salt length in bytes
 * @returns {string} - Hex encoded salt
 */
const generateSalt = (length = 16) => {
  return crypto.randomBytes(length).toString('hex');
};

/**
 * Hash a password using PBKDF2
 * @param {string} password - Password to hash
 * @param {string} salt - Salt for hashing
 * @param {number} iterations - Number of iterations
 * @returns {string} - Hex encoded hash
 */
const hashPassword = (password, salt, iterations = 100000) => {
  return crypto.pbkdf2Sync(
    password,
    salt,
    iterations,
    64, // 512 bits
    'sha256'
  ).toString('hex');
};

/**
 * Verify a password against a hash
 * @param {string} password - Password to verify
 * @param {string} salt - Salt used for hashing
 * @param {string} storedHash - Stored hash to compare against
 * @returns {boolean}
 */
const verifyPassword = (password, salt, storedHash) => {
  const hash = hashPassword(password, salt);
  // Use timing-safe comparison to prevent timing attacks
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(storedHash));
};

/**
 * Generate a secure session token
 * @param {number} length - Token length in bytes
 * @returns {string} - Base64 encoded token
 */
const generateSessionToken = (length = 32) => {
  return crypto.randomBytes(length).toString('base64');
};

/**
 * Create HMAC signature for request verification
 * @param {string} data - Data to sign
 * @param {string} secret - Secret key
 * @returns {string} - Hex encoded signature
 */
const createHMAC = (data, secret) => {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
};

/**
 * Verify HMAC signature
 * @param {string} data - Original data
 * @param {string} signature - Signature to verify
 * @param {string} secret - Secret key
 * @returns {boolean}
 */
const verifyHMAC = (data, signature, secret) => {
  const expected = createHMAC(data, secret);
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
};

// ============================================
// EXPORTS
// ============================================

module.exports = {
  // CryptoJS encryption (for compatibility)
  encrypt,
  decrypt,

  // Native encryption (more secure)
  encryptNative,
  decryptNative,

  // Hashing utilities
  generateSalt,
  hashPassword,
  verifyPassword,

  // Token/signature utilities
  generateSessionToken,
  createHMAC,
  verifyHMAC
};
