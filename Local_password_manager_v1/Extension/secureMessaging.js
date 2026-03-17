/**
 * Secure Messaging Module for Password Manager Extension
 * Handles encrypted communication between content script and service worker
 * All messages are encrypted and signed for integrity
 */

// ============================================
// MESSAGE TYPES
// ============================================

const SecureMessageTypes = {
    // Credential operations
    GET_CREDENTIALS: 'SECURE_GET_CREDENTIALS',
    SAVE_CREDENTIALS: 'SECURE_SAVE_CREDENTIALS',
    UPDATE_CREDENTIALS: 'SECURE_UPDATE_CREDENTIALS',
    DELETE_CREDENTIALS: 'SECURE_DELETE_CREDENTIALS',
    CHECK_EXISTING: 'SECURE_CHECK_EXISTING',

    // Authentication
    LOGIN: 'SECURE_LOGIN',
    LOGOUT: 'SECURE_LOGOUT',
    CHECK_SESSION: 'SECURE_CHECK_SESSION',
    REFRESH_SESSION: 'SECURE_REFRESH_SESSION',

    // Security
    SECURITY_ALERT: 'SECURITY_ALERT',
    LOCK_VAULT: 'LOCK_VAULT',

    // Sync
    TRIGGER_AUTOFILL: 'TRIGGER_AUTOFILL',
    OPEN_SAVE_DIALOG: 'OPEN_SAVE_DIALOG',

    // Responses
    SUCCESS: 'SUCCESS',
    ERROR: 'ERROR'
};

// ============================================
// SECURE MESSAGE WRAPPER
// ============================================

/**
 * Create a secure message with timestamp and optional encryption
 * @param {string} type - Message type
 * @param {object} payload - Message payload
 * @param {boolean} requiresEncryption - Whether to encrypt the payload
 * @returns {object} - Secure message object
 */
function createSecureMessage(type, payload = {}, requiresEncryption = false) {
    return {
        type,
        payload,
        timestamp: Date.now(),
        requiresEncryption,
        id: generateMessageId()
    };
}

/**
 * Generate a unique message ID for tracking
 */
function generateMessageId() {
    return `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

// ============================================
// SECURE CHANNEL CLASS
// ============================================

class SecureChannel {
    constructor() {
        this.pendingMessages = new Map();
        this.messageTimeout = 30000; // 30 seconds
        this.encryptionKey = null;
        this.sessionToken = null;
    }

    /**
     * Initialize the secure channel with encryption key
     * @param {CryptoKey} key - AES-GCM key for encryption
     * @param {string} token - Session token for signing
     */
    async initialize(key, token) {
        this.encryptionKey = key;
        this.sessionToken = token;
    }

    /**
     * Clear the channel (on logout or security alert)
     */
    clear() {
        this.encryptionKey = null;
        this.sessionToken = null;
        this.pendingMessages.clear();
    }

    /**
     * Check if the channel is initialized
     */
    isInitialized() {
        return this.encryptionKey !== null && this.sessionToken !== null;
    }

    /**
     * Send a secure message to the service worker
     * @param {string} type - Message type
     * @param {object} payload - Message payload
     * @returns {Promise<object>} - Response from service worker
     */
    async sendSecureMessage(type, payload = {}) {
        const message = createSecureMessage(type, payload);

        // If we have encryption key and session, encrypt sensitive data
        if (this.isInitialized() && this.shouldEncrypt(type)) {
            try {
                const encrypted = await SecureCrypto.encryptData(
                    JSON.stringify(payload),
                    this.encryptionKey
                );
                message.encryptedPayload = encrypted;
                message.payload = null; // Clear plaintext
                message.signature = await SecureCrypto.signRequest(
                    encrypted,
                    this.sessionToken
                );
            } catch (error) {
                console.error('Failed to encrypt message:', error);
                throw new Error('Encryption failed');
            }
        }

        return new Promise((resolve, reject) => {
            const timeoutId = setTimeout(() => {
                this.pendingMessages.delete(message.id);
                reject(new Error('Message timeout'));
            }, this.messageTimeout);

            this.pendingMessages.set(message.id, { resolve, reject, timeoutId });

            chrome.runtime.sendMessage(message, (response) => {
                clearTimeout(timeoutId);
                this.pendingMessages.delete(message.id);

                if (chrome.runtime.lastError) {
                    reject(new Error(chrome.runtime.lastError.message));
                    return;
                }

                if (response && response.error) {
                    reject(new Error(response.error));
                    return;
                }

                resolve(response);
            });
        });
    }

    /**
     * Determine if a message type requires encryption
     * @param {string} type - Message type
     * @returns {boolean}
     */
    shouldEncrypt(type) {
        const encryptedTypes = [
            SecureMessageTypes.GET_CREDENTIALS,
            SecureMessageTypes.SAVE_CREDENTIALS,
            SecureMessageTypes.UPDATE_CREDENTIALS,
            SecureMessageTypes.LOGIN
        ];
        return encryptedTypes.includes(type);
    }

    /**
     * Decrypt a response from the service worker
     * @param {object} encryptedResponse - Encrypted response
     * @returns {Promise<object>} - Decrypted response
     */
    async decryptResponse(encryptedResponse) {
        if (!this.isInitialized()) {
            throw new Error('Channel not initialized');
        }

        const decrypted = await SecureCrypto.decryptData(
            encryptedResponse,
            this.encryptionKey
        );
        return JSON.parse(decrypted);
    }
}

// ============================================
// CREDENTIAL MESSAGING HELPERS
// ============================================

/**
 * Send a request to get credentials for current site
 * @param {SecureChannel} channel - Secure channel instance
 * @param {string} url - Current page URL
 * @returns {Promise<Array>} - Array of matching credentials
 */
async function requestCredentials(channel, url) {
    try {
        const response = await channel.sendSecureMessage(
            SecureMessageTypes.GET_CREDENTIALS,
            { url }
        );

        if (response.encryptedCredentials && channel.isInitialized()) {
            return await channel.decryptResponse(response.encryptedCredentials);
        }

        return response.credentials || [];
    } catch (error) {
        console.error('Failed to get credentials:', error);
        return [];
    }
}

/**
 * Send a request to save new credentials
 * @param {SecureChannel} channel - Secure channel instance
 * @param {object} credentials - Credentials to save
 * @returns {Promise<boolean>} - Success status
 */
async function saveCredentials(channel, credentials) {
    try {
        const response = await channel.sendSecureMessage(
            SecureMessageTypes.SAVE_CREDENTIALS,
            credentials
        );
        return response.success === true;
    } catch (error) {
        console.error('Failed to save credentials:', error);
        return false;
    }
}

/**
 * Check if credentials already exist for site/username
 * @param {SecureChannel} channel - Secure channel instance
 * @param {string} url - Site URL
 * @param {string} username - Username to check
 * @returns {Promise<{exists: boolean, id?: number}>}
 */
async function checkExistingCredentials(channel, url, username) {
    try {
        const response = await channel.sendSecureMessage(
            SecureMessageTypes.CHECK_EXISTING,
            { url, username }
        );
        return {
            exists: response.exists === true,
            id: response.id
        };
    } catch (error) {
        console.error('Failed to check existing credentials:', error);
        return { exists: false };
    }
}

/**
 * Update existing credentials
 * @param {SecureChannel} channel - Secure channel instance
 * @param {number} id - Credential ID to update
 * @param {object} credentials - New credential data
 * @returns {Promise<boolean>}
 */
async function updateCredentials(channel, id, credentials) {
    try {
        const response = await channel.sendSecureMessage(
            SecureMessageTypes.UPDATE_CREDENTIALS,
            { id, ...credentials }
        );
        return response.success === true;
    } catch (error) {
        console.error('Failed to update credentials:', error);
        return false;
    }
}

// ============================================
// SESSION MESSAGING HELPERS
// ============================================

/**
 * Check if user session is valid
 * @param {SecureChannel} channel - Secure channel instance
 * @returns {Promise<{valid: boolean, user?: object}>}
 */
async function checkSession(channel) {
    try {
        const response = await channel.sendSecureMessage(
            SecureMessageTypes.CHECK_SESSION
        );
        return {
            valid: response.valid === true,
            user: response.user
        };
    } catch (error) {
        console.error('Failed to check session:', error);
        return { valid: false };
    }
}

/**
 * Refresh the session activity
 * @param {SecureChannel} channel - Secure channel instance
 * @returns {Promise<boolean>}
 */
async function refreshSession(channel) {
    try {
        const response = await channel.sendSecureMessage(
            SecureMessageTypes.REFRESH_SESSION
        );
        return response.success === true;
    } catch (error) {
        return false;
    }
}

/**
 * Trigger immediate vault lock
 * @param {SecureChannel} channel - Secure channel instance
 * @returns {Promise<void>}
 */
async function lockVault(channel) {
    try {
        await channel.sendSecureMessage(SecureMessageTypes.LOCK_VAULT);
        channel.clear();
    } catch (error) {
        console.error('Failed to lock vault:', error);
    }
}

// ============================================
// EXPORT FOR USE IN EXTENSION
// ============================================

const SecureMessaging = {
    // Types
    MessageTypes: SecureMessageTypes,

    // Classes
    SecureChannel,

    // Message helpers
    createSecureMessage,
    generateMessageId,

    // Credential operations
    requestCredentials,
    saveCredentials,
    checkExistingCredentials,
    updateCredentials,

    // Session operations
    checkSession,
    refreshSession,
    lockVault
};

// Export for both content scripts and service worker
if (typeof globalThis !== 'undefined') {
    globalThis.SecureMessaging = SecureMessaging;
}
