/**
 * Secure Cryptography Module for Password Manager Extension
 * Uses Web Crypto API (SubtleCrypto) for client-side encryption
 * All credentials are encrypted before transmission to prevent interception
 */

// ============================================
// UTILITY FUNCTIONS
// ============================================

/**
 * Convert ArrayBuffer/Uint8Array to Base64 string
 */
function arrayToBase64(buffer) {
    const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Convert Base64 string to Uint8Array
 */
function base64ToArray(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Convert string to Uint8Array
 */
function stringToArray(str) {
    return new TextEncoder().encode(str);
}

/**
 * Convert Uint8Array to string
 */
function arrayToString(arr) {
    return new TextDecoder().decode(arr);
}

/**
 * Generate a random salt for key derivation
 */
function generateSalt(length = 16) {
    return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Generate a random IV for AES-GCM encryption
 */
function generateIV() {
    return crypto.getRandomValues(new Uint8Array(12)); // 96 bits for AES-GCM
}

// ============================================
// KEY DERIVATION
// ============================================

/**
 * Derive a cryptographic key from a master password using PBKDF2
 * @param {string} masterPassword - The user's master password
 * @param {Uint8Array|string} salt - Salt for key derivation
 * @returns {Promise<CryptoKey>} - Derived AES-GCM key
 */
async function deriveKey(masterPassword, salt) {
    const encoder = new TextEncoder();
    const saltArray = typeof salt === 'string' ? base64ToArray(salt) : salt;

    // Import the password as raw key material
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(masterPassword),
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );

    // Derive a 256-bit AES-GCM key
    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: saltArray,
            iterations: 100000, // High iteration count for security
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false, // Non-extractable for security
        ['encrypt', 'decrypt']
    );
}

/**
 * Derive a key specifically for HMAC signing
 * @param {string} sessionToken - Session token for signing
 * @returns {Promise<CryptoKey>} - HMAC key
 */
async function deriveHMACKey(sessionToken) {
    const encoder = new TextEncoder();
    return crypto.subtle.importKey(
        'raw',
        encoder.encode(sessionToken),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign', 'verify']
    );
}

// ============================================
// ENCRYPTION / DECRYPTION
// ============================================

/**
 * Encrypt data using AES-GCM
 * @param {string|object} data - Data to encrypt
 * @param {CryptoKey} key - AES-GCM key
 * @returns {Promise<{iv: string, data: string, tag: string}>} - Encrypted payload with IV and tag
 */
async function encryptData(data, key) {
    const iv = generateIV();
    const dataString = typeof data === 'object' ? JSON.stringify(data) : data;

    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        stringToArray(dataString)
    );

    // Web Crypto appends the tag (16 bytes) at the end of the ciphertext
    const tagLength = 16;
    const tag = encrypted.slice(encrypted.byteLength - tagLength);
    const ciphertext = encrypted.slice(0, encrypted.byteLength - tagLength);

    return {
        iv: arrayToBase64(iv),
        data: arrayToBase64(ciphertext),
        tag: arrayToBase64(tag)
    };
}

/**
 * Decrypt data using AES-GCM
 * @param {{iv: string, data: string, tag: string}} encryptedPayload - Encrypted data with IV and tag
 * @param {CryptoKey} key - AES-GCM key
 * @returns {Promise<string>} - Decrypted data
 */
async function decryptData(encryptedPayload, key) {
    try {
        const ciphertext = base64ToArray(encryptedPayload.data);
        const tag = base64ToArray(encryptedPayload.tag);
        const iv = base64ToArray(encryptedPayload.iv);

        // Concatenate ciphertext and tag for Web Crypto
        const dataToDecrypt = new Uint8Array(ciphertext.length + tag.length);
        dataToDecrypt.set(ciphertext);
        dataToDecrypt.set(tag, ciphertext.length);

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            dataToDecrypt
        );
        return arrayToString(decrypted);
    } catch (error) {
        console.error('Decryption failed:', error);
        throw new Error('Failed to decrypt data - possibly corrupted or wrong key');
    }
}

/**
 * Encrypt a credential payload for secure transmission
 * @param {{username: string, password: string}} credentials - Credentials to encrypt
 * @param {CryptoKey} key - Encryption key
 * @returns {Promise<{iv: string, data: string, timestamp: number}>}
 */
async function encryptCredentials(credentials, key) {
    const payload = {
        ...credentials,
        timestamp: Date.now() // For replay attack protection
    };
    const encrypted = await encryptData(payload, key);
    return {
        ...encrypted,
        timestamp: payload.timestamp
    };
}

/**
 * Decrypt a credential payload
 * @param {{iv: string, data: string}} encryptedCredentials - Encrypted credentials
 * @param {CryptoKey} key - Decryption key
 * @returns {Promise<{username: string, password: string}>}
 */
async function decryptCredentials(encryptedCredentials, key) {
    const decrypted = await decryptData(encryptedCredentials, key);
    return JSON.parse(decrypted);
}

// ============================================
// REQUEST SIGNING (HMAC)
// ============================================

/**
 * Sign a request payload using HMAC-SHA256
 * @param {object} payload - Request payload to sign
 * @param {string} sessionToken - Session token for signing
 * @returns {Promise<string>} - Base64 encoded signature
 */
async function signRequest(payload, sessionToken) {
    const key = await deriveHMACKey(sessionToken);
    const data = JSON.stringify(payload) + Date.now().toString();

    const signature = await crypto.subtle.sign(
        'HMAC',
        key,
        stringToArray(data)
    );

    return arrayToBase64(signature);
}

/**
 * Verify an HMAC signature
 * @param {object} payload - Original payload
 * @param {string} signature - Base64 encoded signature to verify
 * @param {string} sessionToken - Session token
 * @param {number} timestamp - Original timestamp
 * @returns {Promise<boolean>} - True if signature is valid
 */
async function verifySignature(payload, signature, sessionToken, timestamp) {
    const key = await deriveHMACKey(sessionToken);
    const data = JSON.stringify(payload) + timestamp.toString();

    return crypto.subtle.verify(
        'HMAC',
        key,
        base64ToArray(signature),
        stringToArray(data)
    );
}

// ============================================
// SESSION KEY MANAGEMENT
// ============================================

/**
 * Generate a session encryption key from user credentials
 * Creates a derived key that can be stored securely
 * @param {string} password - User's master password
 * @param {string} salt - User-specific salt (can be derived from username)
 * @returns {Promise<{key: CryptoKey, salt: string}>}
 */
async function generateSessionKey(password, salt) {
    const saltArray = salt ? base64ToArray(salt) : generateSalt();
    const key = await deriveKey(password, saltArray);
    return {
        key,
        salt: arrayToBase64(saltArray)
    };
}

/**
 * Generate a random session token
 * @returns {string} - Base64 encoded random token
 */
function generateSessionToken() {
    const token = crypto.getRandomValues(new Uint8Array(32));
    return arrayToBase64(token);
}

// ============================================
// PASSWORD HASHING (for local verification)
// ============================================

/**
 * Hash a password for local storage/verification using PBKDF2
 * @param {string} password - Password to hash
 * @param {string} salt - Salt for hashing
 * @returns {Promise<string>} - Base64 encoded hash
 */
async function hashPassword(password, salt) {
    const encoder = new TextEncoder();
    const saltArray = typeof salt === 'string' ? base64ToArray(salt) : salt;

    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    );

    const hash = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: saltArray,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        256
    );

    return arrayToBase64(hash);
}

// ============================================
// EXPORT FOR USE IN EXTENSION
// ============================================

// Make functions available globally for content scripts
const SecureCrypto = {
    // Utilities
    arrayToBase64,
    base64ToArray,
    generateSalt,
    generateIV,
    generateSessionToken,

    // Key derivation
    deriveKey,
    generateSessionKey,

    // Encryption
    encryptData,
    decryptData,
    encryptCredentials,
    decryptCredentials,

    // Signing
    signRequest,
    verifySignature,

    // Hashing
    hashPassword,

    /**
     * Generate a strong random password
     * @param {object} options - Password generation options
     * @returns {string} - Generated password
     */
    generatePassword(options = {}) {
        const {
            length = 16,
            useUppercase = true,
            useNumbers = true,
            useSymbols = true
        } = options;

        const lowercase = 'abcdefghijklmnopqrstuvwxyz';
        const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const numbers = '0123456789';
        const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';

        let charset = lowercase;
        if (useUppercase) charset += uppercase;
        if (useNumbers) charset += numbers;
        if (useSymbols) charset += symbols;

        let password = '';
        const array = new Uint32Array(length);
        crypto.getRandomValues(array);

        for (let i = 0; i < length; i++) {
            password += charset[array[i] % charset.length];
        }

        return password;
    },

    /**
     * Import a PEM formatted RSA Public Key
     * @param {string} pem - PEM string
     * @returns {Promise<CryptoKey>}
     */
    async importPublicKey(pem) {
        // Remove PEM headers and footers
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";
        const pemContents = pem.substring(
            pem.indexOf(pemHeader) + pemHeader.length,
            pem.indexOf(pemFooter)
        ).replace(/\s/g, '');

        const binaryDer = base64ToArray(pemContents);

        return crypto.subtle.importKey(
            "spki",
            binaryDer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256",
            },
            true,
            ["encrypt"]
        );
    },

    /**
     * Encrypt data using RSA-OAEP public key
     * @param {Uint8Array} data - Data to encrypt
     * @param {CryptoKey} publicKey - RSA Public Key
     * @returns {Promise<string>} - Base64 encoded encrypted data
     */
    async encryptWithRSA(data, publicKey) {
        const encrypted = await crypto.subtle.encrypt(
            {
                name: "RSA-OAEP"
            },
            publicKey,
            data
        );
        return arrayToBase64(encrypted);
    },

    /**
     * Generate a random AES-256 key for transport
     * @returns {Promise<CryptoKey>}
     */
    async generateTransportKey() {
        return crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256,
            },
            true,
            ["encrypt", "decrypt"]
        );
    },

    /**
     * Export a CryptoKey to raw bytes
     * @param {CryptoKey} key - Key to export
     * @returns {Promise<Uint8Array>}
     */
    async exportKey(key) {
        const exported = await crypto.subtle.exportKey("raw", key);
        return new Uint8Array(exported);
    }
};

// Export for both content scripts and service worker
if (typeof globalThis !== 'undefined') {
    globalThis.SecureCrypto = SecureCrypto;
}
