/**
 * ╔═══════════════════════════════════════════════════════════════╗
 * ║     ZERO-KNOWLEDGE VAULT ENCRYPTION MODULE                     ║
 * ║     Client-Side Vault Encryption (Backend Never Sees Keys)    ║
 * ╚═══════════════════════════════════════════════════════════════╝
 * 
 * SECURITY PHILOSOPHY:
 * - Master password NEVER leaves this device
 * - Vault encryption key derived locally
 * - Backend stores only ciphertext blobs
 * - Server compromise does NOT leak credentials
 * 
 * ARCHITECTURE:
 * ┌──────────────┐
 * │Master Password│
 * └───────┬───────┘
 *         │ PBKDF2 (600K iterations)
 *         ▼
 * ┌──────────────┐
 * │ Master Key   │
 * └───────┬───────┘
 *         │ HKDF-Expand
 *    ┌────┴────┐
 *    ▼         ▼
 * ┌────┐   ┌────────┐
 * │Auth│   │Vault   │
 * │Key │   │Key     │
 * └────┘   └────┬───┘
 *               │ AES-256-GCM
 *               ▼
 *      ┌──────────────────┐
 *      │ Encrypted Vault  │
 *      │ (JSON ciphertext)│
 *      └──────────────────┘
 */

// ============================================
// CONSTANTS
// ============================================

const CRYPTO_CONFIG = {
    PBKDF2_ITERATIONS: 600000,      // 600K iterations (OWASP 2023 recommendation)
    SALT_LENGTH: 32,                // 256 bits
    KEY_LENGTH: 256,                // AES-256
    IV_LENGTH: 12,                  // 96 bits for AES-GCM
    TAG_LENGTH: 128,                // GCM authentication tag
    VAULT_VERSION: 1                // For future migrations
};

const KEY_PURPOSE = {
    AUTH: 'auth',       // For backend authentication
    VAULT: 'vault',     // For encrypting vault data
    BACKUP: 'backup'    // For recovery codes (future)
};

// ============================================
// KEY DERIVATION
// ============================================

/**
 * Derive a master key from user's password using PBKDF2
 * This is the root of all other keys
 * 
 * @param {string} masterPassword - User's master password
 * @param {Uint8Array|string} salt - User-specific salt
 * @returns {Promise<CryptoKey>} - Master key (non-extractable)
 */
async function deriveMasterKey(masterPassword, salt) {
    const saltArray = typeof salt === 'string' ? base64ToArray(salt) : salt;

    // Import password as key material
    const passwordKey = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(masterPassword),
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );

    // Derive master key using PBKDF2
    const masterKey = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: saltArray,
            iterations: CRYPTO_CONFIG.PBKDF2_ITERATIONS,
            hash: 'SHA-256'
        },
        passwordKey,
        { name: 'HKDF', hash: 'SHA-256' },
        false,  // Non-extractable
        ['deriveBits', 'deriveKey']
    );

    return masterKey;
}

/**
 * Derive a purpose-specific key from master key using HKDF
 * This prevents key reuse across different contexts
 * 
 * @param {CryptoKey} masterKey - Master key from deriveMasterKey
 * @param {string} purpose - One of KEY_PURPOSE values
 * @param {Uint8Array} salt - Additional salt for context separation
 * @returns {Promise<CryptoKey>} - Purpose-specific key
 */
async function derivePurposeKey(masterKey, purpose, salt) {
    const info = new TextEncoder().encode(`PassManager.v1.${purpose}`);

    // Extract bits from master key
    const keyMaterial = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: salt,
            info: info
        },
        masterKey,
        CRYPTO_CONFIG.KEY_LENGTH
    );

    // Import as AES-GCM key for vault encryption
    if (purpose === KEY_PURPOSE.VAULT) {
        return crypto.subtle.importKey(
            'raw',
            keyMaterial,
            { name: 'AES-GCM' },
            false,  // Non-extractable
            ['encrypt', 'decrypt']
        );
    }

    // For auth, just return the raw bits (will be hashed for login)
    return new Uint8Array(keyMaterial);
}

/**
 * Generate all required keys from master password
 * Call this once during login/unlock
 * 
 * @param {string} masterPassword - User's master password
 * @param {string} userSalt - User-specific salt (from backend)
 * @returns {Promise<{authKey: Uint8Array, vaultKey: CryptoKey}>}
 */
async function generateKeys(masterPassword, userSalt) {
    const salt = base64ToArray(userSalt);

    // Derive master key
    const masterKey = await deriveMasterKey(masterPassword, salt);

    // Derive sub-keys
    const authKey = await derivePurposeKey(
        masterKey,
        KEY_PURPOSE.AUTH,
        salt
    );

    const vaultKey = await derivePurposeKey(
        masterKey,
        KEY_PURPOSE.VAULT,
        generateSalt()
    );

    return { authKey, vaultKey };
}

// ============================================
// VAULT ENCRYPTION
// ============================================

/**
 * Encrypt the entire vault
 * Vault structure: { credentials: [...], metadata: {...} }
 * 
 * @param {object} vault - Vault data to encrypt
 * @param {CryptoKey} vaultKey - Encryption key
 * @returns {Promise<{iv: string, ciphertext: string, tag: string, version: number}>}
 */
async function encryptVault(vault, vaultKey) {
    const iv = generateIV();
    const plaintext = JSON.stringify(vault);

    // Encrypt with AES-GCM (provides both confidentiality and authenticity)
    const ciphertext = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv,
            tagLength: CRYPTO_CONFIG.TAG_LENGTH
        },
        vaultKey,
        new TextEncoder().encode(plaintext)
    );

    // GCM includes auth tag in the ciphertext, split it
    const ciphertextArray = new Uint8Array(ciphertext);
    const tag = ciphertextArray.slice(-16); // Last 16 bytes is the tag
    const data = ciphertextArray.slice(0, -16);

    return {
        version: CRYPTO_CONFIG.VAULT_VERSION,
        iv: arrayToBase64(iv),
        ciphertext: arrayToBase64(data),
        tag: arrayToBase64(tag)
    };
}

/**
 * Decrypt the vault
 * 
 * @param {object} encryptedVault - Encrypted vault from backend
 * @param {CryptoKey} vaultKey - Decryption key
 * @returns {Promise<object>} - Decrypted vault object
 * @throws {Error} If decryption fails (wrong key, tampered data, etc.)
 */
async function decryptVault(encryptedVault, vaultKey) {
    try {
        const iv = base64ToArray(encryptedVault.iv);
        const ciphertext = base64ToArray(encryptedVault.ciphertext);
        const tag = base64ToArray(encryptedVault.tag);

        // Reconstruct full ciphertext with tag
        const fullCiphertext = new Uint8Array([...ciphertext, ...tag]);

        // Decrypt with AES-GCM
        const plaintext = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: CRYPTO_CONFIG.TAG_LENGTH
            },
            vaultKey,
            fullCiphertext
        );

        const decryptedText = new TextDecoder().decode(plaintext);
        return JSON.parse(decryptedText);

    } catch (error) {
        console.error('Vault decryption failed:', error);
        throw new Error('Failed to decrypt vault - invalid password or corrupted data');
    }
}

// ============================================
// INDIVIDUAL CREDENTIAL ENCRYPTION (DEPRECATED)
// ============================================
// NOTE: These are legacy functions for the OLD architecture
// where backend encrypted individual credentials.
// REMOVE THESE after migrating to vault-level encryption.

/**
 * @deprecated Use encryptVault instead
 */
async function encryptCredential(credential, key) {
    console.warn('⚠️ encryptCredential is deprecated. Use encryptVault instead.');
    const iv = generateIV();
    const plaintext = JSON.stringify(credential);

    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        new TextEncoder().encode(plaintext)
    );

    return {
        iv: arrayToBase64(iv),
        data: arrayToBase64(ciphertext)
    };
}

/**
 * @deprecated Use decryptVault instead
 */
async function decryptCredential(encryptedCredential, key) {
    console.warn('⚠️ decryptCredential is deprecated. Use decryptVault instead.');
    const iv = base64ToArray(encryptedCredential.iv);
    const ciphertext = base64ToArray(encryptedCredential.data);

    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
    );

    const decryptedText = new TextDecoder().decode(plaintext);
    return JSON.parse(decryptedText);
}

// ============================================
// VAULT OPERATIONS (HIGH-LEVEL API)
// ============================================

/**
 * Add a credential to the vault
 * @param {object} vault - Current vault
 * @param {object} credential - Credential to add {service, username, password}
 * @returns {object} - Updated vault
 */
function addCredential(vault, credential) {
    if (!vault.credentials) {
        vault.credentials = [];
    }

    const newCredential = {
        id: generateId(),
        service: credential.service,
        username: credential.username,
        password: credential.password,
        created_at: Date.now(),
        updated_at: Date.now()
    };

    vault.credentials.push(newCredential);
    vault.metadata = vault.metadata || {};
    vault.metadata.last_modified = Date.now();

    return vault;
}

/**
 * Update a credential in the vault
 * @param {object} vault - Current vault
 * @param {string} credentialId - ID of credential to update
 * @param {object} updates - Fields to update
 * @returns {object} - Updated vault
 */
function updateCredential(vault, credentialId, updates) {
    const index = vault.credentials.findIndex(c => c.id === credentialId);

    if (index === -1) {
        throw new Error('Credential not found');
    }

    vault.credentials[index] = {
        ...vault.credentials[index],
        ...updates,
        updated_at: Date.now()
    };

    vault.metadata.last_modified = Date.now();

    return vault;
}

/**
 * Remove a credential from the vault
 * @param {object} vault - Current vault
 * @param {string} credentialId - ID of credential to remove
 * @returns {object} - Updated vault
 */
function removeCredential(vault, credentialId) {
    vault.credentials = vault.credentials.filter(c => c.id !== credentialId);
    vault.metadata.last_modified = Date.now();

    return vault;
}

/**
 * Find credentials matching a domain
 * @param {object} vault - Decrypted vault
 * @param {string} domain - Domain to match
 * @returns {Array} - Matching credentials
 */
function findCredentialsForDomain(vault, domain) {
    if (!vault.credentials) return [];

    return vault.credentials.filter(cred => {
        try {
            const credDomain = new URL(
                cred.service.startsWith('http') ? cred.service : `https://${cred.service}`
            ).hostname.replace(/^www\./, '').toLowerCase();

            const targetDomain = domain.toLowerCase();

            // Exact match or subdomain match
            return credDomain === targetDomain ||
                credDomain.endsWith('.' + targetDomain) ||
                targetDomain.endsWith('.' + credDomain);
        } catch {
            // Fallback to string matching
            return cred.service.toLowerCase().includes(domain.toLowerCase());
        }
    });
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

function arrayToBase64(buffer) {
    const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArray(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function generateSalt(length = CRYPTO_CONFIG.SALT_LENGTH) {
    return crypto.getRandomValues(new Uint8Array(length));
}

function generateIV() {
    return crypto.getRandomValues(new Uint8Array(CRYPTO_CONFIG.IV_LENGTH));
}

function generateId() {
    return `cred_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// ============================================
// EXPORTS
// ============================================

const VaultCrypto = {
    // Key derivation
    deriveMasterKey,
    derivePurposeKey,
    generateKeys,

    // Vault encryption
    encryptVault,
    decryptVault,

    // Vault operations
    addCredential,
    updateCredential,
    removeCredential,
    findCredentialsForDomain,

    // Utilities
    generateSalt,
    arrayToBase64,
    base64ToArray,

    // Constants
    CRYPTO_CONFIG,
    KEY_PURPOSE
};

// Export for use in extension
if (typeof globalThis !== 'undefined') {
    globalThis.VaultCrypto = VaultCrypto;
}
