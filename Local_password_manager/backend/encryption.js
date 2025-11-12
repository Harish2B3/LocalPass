
const CryptoJS = require('crypto-js');

// WARNING: In a real application, this key MUST be stored securely in an environment variable
// (e.g., process.env.ENCRYPTION_KEY) and should be a long, random string.
// Do not hardcode secrets in your source code in production.
//
// FIX: The AES encryption key must be a specific length (16, 24, or 32 bytes).
// The previous key had an invalid length, causing decryption to fail silently.
// This key is now 32 bytes long to support AES-256.
const SECRET_KEY = 'a-32-byte-long-super-secret-key!';

const encrypt = (text) => {
  console.log('Encrypting text...');
  if (text === null || typeof text === 'undefined') {
    console.error("Encryption input is null or undefined. Encrypting an empty string instead.");
    text = '';
  }
  console.log('Input text length:', text.toString().length);
  const iv = CryptoJS.lib.WordArray.random(16);
  const encrypted = CryptoJS.AES.encrypt(text.toString(), CryptoJS.enc.Utf8.parse(SECRET_KEY), {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });
  const result = {
    iv: iv.toString(CryptoJS.enc.Hex),
    content: encrypted.toString()
  };
  console.log('Encryption successful.');
  return result;
};

const decrypt = (hash) => {
  console.log('Decrypting hash...');
  if (!hash || !hash.iv || !hash.content) {
    console.log('Hash is empty or invalid, returning empty string.');
    return '';
  }
  try {
    // The key must be parsed from UTF8 into a WordArray.
    const key = CryptoJS.enc.Utf8.parse(SECRET_KEY);
    // The IV must be parsed from Hex into a WordArray.
    const iv = CryptoJS.enc.Hex.parse(hash.iv);

    console.log('Decrypting content...');
    // Decrypt using the Base64-encoded content string, with the parsed key and IV.
    const decryptedBytes = CryptoJS.AES.decrypt(hash.content, key, {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    });
    
    // Convert the decrypted WordArray back to a UTF8 string.
    const decryptedText = decryptedBytes.toString(CryptoJS.enc.Utf8);
    
    // With an invalid key, crypto-js often returns an empty WordArray (sigBytes: 0), 
    // which results in an empty string. This is indistinguishable from a legitimately empty password.
    // A key of the correct length is critical for success.
    if (decryptedText) {
      console.log(`Decryption successful. Decrypted text length: ${decryptedText.length}`);
    } else {
      // This case handles both legitimately empty passwords and decryption failures (e.g. wrong key).
      console.log('Decryption resulted in an empty string.');
    }
    
    // This check handles a more specific error: data was decrypted but is not valid UTF-8.
    if (!decryptedText && decryptedBytes.sigBytes > 0) {
        console.warn('Decryption warning: Data could not be represented as a UTF-8 string, indicating potential corruption.');
    }

    return decryptedText;
  } catch (error) {
    console.error('An exception occurred during decryption:', error);
    return ''; // Return an empty string on error to prevent crashes.
  }
};

module.exports = { encrypt, decrypt };
