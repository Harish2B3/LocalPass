/**
 * ╔═══════════════════════════════════════════════════════════════╗
 * ║   ZERO-KNOWLEDGE SERVICE WORKER (REFACTORED)                  ║
 * ║   All vault encryption happens here, never in content script  ║
 * ╚═══════════════════════════════════════════════════════════════╝
 */

importScripts('crypto.js', 'vaultCrypto.js');

const API_BASE = 'http://localhost:3001/api';
const SESSION_TIMEOUT = 15 * 60 * 1000; // 15 minutes (reduced from 24h)
const MAX_FAILED_UNLOCK_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000;

// ============================================
// SESSION MANAGER (Enhanced)
// ============================================

class SecureSessionManager {
    constructor() {
        this.failedAttempts = 0;
        this.lockoutUntil = null;
        this.vaultKey = null; // Stored in memory only
        this.decryptedVault = null; // Cached decrypted vault
    }

    /**
     * Unlock vault with master password
     * This is the ONLY place where the vault is decrypted
     */
    async unlockVault(userId, masterPassword) {
        if (this.isLockedOut()) {
            const remaining = Math.ceil(this.getRemainingLockoutTime() / 60000);
            throw new Error(`Too many failed attempts. Try again in ${remaining} minutes.`);
        }

        try {
            // 1. Fetch user's salt from backend
            const userInfo = await this.fetchUserInfo(userId);

            // 2. Derive keys from master password
            const { authKey, vaultKey } = await VaultCrypto.generateKeys(
                masterPassword,
                userInfo.salt
            );

            // 3. Verify master password by attempting to fetch & decrypt vault
            const encryptedVault = await this.fetchEncryptedVault(userId);

            // 4. Decrypt vault (will throw if wrong password)
            const vault = await VaultCrypto.decryptVault(encryptedVault, vaultKey);

            // 5. Store vault key in memory (non-extractable CryptoKey)
            this.vaultKey = vaultKey;
            this.decryptedVault = vault;

            // 6. Create session
            await chrome.storage.local.set({
                user: {
                    id: userId,
                    username: userInfo.username
                },
                sessionCreated: Date.now(),
                lastActivity: Date.now(),
                isUnlocked: true
            });

            this.failedAttempts = 0;
            this.lockoutUntil = null;

            console.log('✅ Vault unlocked successfully');
            return { success: true };

        } catch (error) {
            console.error('Vault unlock failed:', error);

            this.failedAttempts++;
            if (this.failedAttempts >= MAX_FAILED_UNLOCK_ATTEMPTS) {
                this.lockoutUntil = Date.now() + LOCKOUT_DURATION;
            }

            throw new Error('Invalid master password');
        }
    }

    /**
     * Lock vault (clear keys from memory)
     */
    async lockVault() {
        // Wipe sensitive data from memory
        this.vaultKey = null;
        this.decryptedVault = null;

        await chrome.storage.local.set({ isUnlocked: false });
        await chrome.storage.session.clear();

        console.log('🔒 Vault locked');
    }

    /**
     * Check if vault is unlocked
     */
    async isUnlocked() {
        const { isUnlocked, lastActivity } = await chrome.storage.local.get([
            'isUnlocked',
            'lastActivity'
        ]);

        if (!isUnlocked || !this.vaultKey) {
            return false;
        }

        // Check for timeout
        const now = Date.now();
        if (lastActivity && (now - lastActivity > SESSION_TIMEOUT)) {
            await this.lockVault();
            return false;
        }

        // Update activity timestamp
        await chrome.storage.local.set({ lastActivity: now });

        return true;
    }

    /**
     * Get credentials for a specific domain
     * CRITICAL: Only returns matching credentials, never the full vault
     */
    async getCredentialsForDomain(domain) {
        if (!(await this.isUnlocked())) {
            throw new Error('Vault is locked');
        }

        // Validate domain
        if (!this.isValidDomain(domain)) {
            throw new Error('Invalid domain');
        }

        // Find matching credentials
        const matches = VaultCrypto.findCredentialsForDomain(
            this.decryptedVault,
            domain
        );

        // Audit log
        console.log(`🔍 Vault access: ${domain} (${matches.length} matches)`);

        return matches;
    }

    /**
     * Add new credential to vault
     */
    async addCredential(credential) {
        if (!(await this.isUnlocked())) {
            throw new Error('Vault is locked');
        }

        // Update vault in memory
        VaultCrypto.addCredential(this.decryptedVault, credential);

        // Encrypt and save to backend
        await this.saveVault();

        console.log(`✅ Added credential for ${credential.service}`);
    }

    /**
     * Update existing credential
     */
    async updateCredential(credentialId, updates) {
        if (!(await this.isUnlocked())) {
            throw new Error('Vault is locked');
        }

        VaultCrypto.updateCredential(this.decryptedVault, credentialId, updates);
        await this.saveVault();

        console.log(`✅ Updated credential ${credentialId}`);
    }

    /**
     * Remove credential
     */
    async removeCredential(credentialId) {
        if (!(await this.isUnlocked())) {
            throw new Error('Vault is locked');
        }

        VaultCrypto.removeCredential(this.decryptedVault, credentialId);
        await this.saveVault();

        console.log(`🗑️ Removed credential ${credentialId}`);
    }

    /**
     * Save encrypted vault to backend
     */
    async saveVault() {
        const { user } = await chrome.storage.local.get(['user']);

        if (!user || !this.vaultKey) {
            throw new Error('No active session');
        }

        // Encrypt vault
        const encryptedVault = await VaultCrypto.encryptVault(
            this.decryptedVault,
            this.vaultKey
        );

        // Send to backend
        await fetch(`${API_BASE}/vault/${user.id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                vault: encryptedVault
            })
        });
    }

    /**
     * Fetch user info (salt) from backend
     */
    async fetchUserInfo(userId) {
        const response = await fetch(`${API_BASE}/users/${userId}`);
        if (!response.ok) {
            throw new Error('Failed to fetch user info');
        }
        return response.json();
    }

    /**
     * Fetch encrypted vault from backend
     */
    async fetchEncryptedVault(userId) {
        const response = await fetch(`${API_BASE}/vault/${userId}`);
        if (!response.ok) {
            throw new Error('Failed to fetch vault');
        }
        const data = await response.json();
        return data.vault;
    }

    /**
     * Validate domain format
     */
    isValidDomain(domain) {
        return /^[a-z0-9.-]+$/i.test(domain);
    }

    isLockedOut() {
        if (this.lockoutUntil && Date.now() < this.lockoutUntil) {
            return true;
        }
        if (this.lockoutUntil && Date.now() >= this.lockoutUntil) {
            this.lockoutUntil = null;
            this.failedAttempts = 0;
        }
        return false;
    }

    getRemainingLockoutTime() {
        if (!this.lockoutUntil) return 0;
        return Math.max(0, this.lockoutUntil - Date.now());
    }
}

const sessionManager = new SecureSessionManager();

// ============================================
// MESSAGE HANDLERS
// ============================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message, sender)
        .then(sendResponse)
        .catch(error => {
            console.error('Message handler error:', error);
            sendResponse({ error: error.message });
        });
    return true; // Keep channel open for async response
});

async function handleMessage(message, sender) {
    const { type, data } = message;

    switch (type) {
        case 'UNLOCK_VAULT':
            return handleUnlockVault(data);

        case 'LOCK_VAULT':
            await sessionManager.lockVault();
            return { success: true };

        case 'CHECK_UNLOCK_STATUS':
            const isUnlocked = await sessionManager.isUnlocked();
            return { isUnlocked };

        case 'GET_CREDENTIALS':
            return handleGetCredentials(message.url || message.domain);

        case 'SAVE_CREDENTIAL':
            return handleSaveCredential(data);

        case 'UPDATE_CREDENTIAL':
            return handleUpdateCredential(data);

        case 'DELETE_CREDENTIAL':
            return handleDeleteCredential(data);

        default:
            return { error: 'Unknown message type' };
    }
}

/**
 * Handle vault unlock request
 */
async function handleUnlockVault(data) {
    try {
        const { userId, masterPassword } = data;

        if (!userId || !masterPassword) {
            return { success: false, error: 'Missing credentials' };
        }

        await sessionManager.unlockVault(userId, masterPassword);
        return { success: true };

    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Handle credential fetch for autofill
 * SECURITY: Only returns credentials for exact domain match
 */
async function handleGetCredentials(url) {
    try {
        if (!url) {
            return { error: 'URL required', credentials: [] };
        }

        // Extract domain
        const domain = new URL(url).hostname.replace(/^www\./, '').toLowerCase();

        // Get matching credentials
        const credentials = await sessionManager.getCredentialsForDomain(domain);

        return { credentials };

    } catch (error) {
        console.error('Get credentials error:', error);
        return { error: error.message, credentials: [] };
    }
}

/**
 * Handle save credential request
 */
async function handleSaveCredential(data) {
    try {
        const { service, username, password } = data;

        if (!service || !password) {
            return { success: false, error: 'Service and password required' };
        }

        await sessionManager.addCredential({
            service,
            username: username || '',
            password
        });

        return { success: true };

    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Handle update credential request
 */
async function handleUpdateCredential(data) {
    try {
        const { id, service, username, password } = data;

        if (!id) {
            return { success: false, error: 'Credential ID required' };
        }

        await sessionManager.updateCredential(id, {
            service,
            username,
            password
        });

        return { success: true };

    } catch (error) {
        return { success: false, error: error.message };
    }
}

/**
 * Handle delete credential request
 */
async function handleDeleteCredential(data) {
    try {
        const { id } = data;

        if (!id) {
            return { success: false, error: 'Credential ID required' };
        }

        await sessionManager.removeCredential(id);
        return { success: true };

    } catch (error) {
        return { success: false, error: error.message };
    }
}

// ============================================
// AUTO-LOCK MECHANISMS
// ============================================

// Lock on idle
chrome.idle.onStateChanged.addListener(async (state) => {
    if (state === 'locked') {
        console.log('💤 System locked - locking vault');
        await sessionManager.lockVault();
    }
});

// Lock on browser close (startup)
chrome.runtime.onStartup.addListener(async () => {
    console.log('🔒 Browser started - locking vault');
    await sessionManager.lockVault();
});

// Periodic session check
chrome.alarms.create('sessionCheck', { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === 'sessionCheck') {
        const unlocked = await sessionManager.isUnlocked();
        if (!unlocked) {
            // Notify popup if open
            try {
                await chrome.runtime.sendMessage({ type: 'VAULT_LOCKED' });
            } catch {
                // Popup not open
            }
        }
    }
});

// ============================================
// INSTALLATION
// ============================================

chrome.runtime.onInstalled.addListener((details) => {
    if (details.reason === 'install') {
        console.log('🎉 PassManager installed - Welcome!');
    } else if (details.reason === 'update') {
        console.log('✨ PassManager updated to v3.0.0');
    }
});
