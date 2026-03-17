/**
 * Secure Service Worker for Password Manager Extension
 * Handles:
 * - Secure API communication with signature verification
 * - Session management with encryption
 * - Rate limiting and security checks
 * - Encrypted credential storage
 */

// ============================================
// CONFIGURATION
// ============================================

const DEFAULT_API_BASE = 'http://localhost:3001/api';
let currentApiBase = DEFAULT_API_BASE;

// ============================================
// IMPORT CRYPTO MODULE
// ============================================

importScripts('crypto.js', 'secureClient.js', 'discoveryService.js', 'secureMessaging.js');

let secureClient = new SecureClient(currentApiBase);
const discoveryService = new DiscoveryService();

/**
 * Update the active API base and re-initialize the secure client
 */
async function updateApiBase(newBase) {
    console.log(`Switching API base to: ${newBase}`);
    currentApiBase = newBase;
    secureClient = new SecureClient(currentApiBase);
    if (typeof apiClient !== 'undefined') apiClient.baseUrl = currentApiBase;

    // Save both the full URL and the specific IP as "Last Known Good"
    const storageData = { activeApiBase: newBase };

    try {
        const url = new URL(newBase);
        if (url.hostname && url.hostname !== 'localhost') {
            storageData.lastSuccessfulIp = url.hostname;
        }
    } catch (e) {
        // Not a standard URL, skip IP extraction
    }

    await chrome.storage.local.set(storageData);
}

// Load persisted API base on startup
chrome.storage.local.get(['activeApiBase'], (result) => {
    if (result.activeApiBase) {
        updateApiBase(result.activeApiBase);
    }
});

// ============================================
// SESSION MANAGER
// ============================================

class SessionManager {
    constructor() {
        this.failedAttempts = 0;
        this.lockoutUntil = null;
    }

    async createSession(user, derivedKey = null) {
        const sessionToken = SecureCrypto.generateSessionToken();
        const now = Date.now();

        await chrome.storage.local.set({
            user: {
                id: user.id,
                username: user.username
            },
            sessionToken: sessionToken,
            lastActivity: now,
            sessionCreated: now
        });

        // Store encryption key in session storage (more secure, cleared on browser close)
        if (derivedKey) {
            await chrome.storage.session.set({
                encryptionKeyInfo: {
                    salt: user.salt || SecureCrypto.arrayToBase64(SecureCrypto.generateSalt())
                }
            });
        }

        this.failedAttempts = 0;
        this.lockoutUntil = null;

        return sessionToken;
    }

    async validateSession() {
        try {
            const { user, lastActivity, sessionToken } = await chrome.storage.local.get([
                'user', 'lastActivity', 'sessionToken'
            ]);

            if (!user || !sessionToken) {
                return { valid: false, reason: 'Not logged in' };
            }

            const now = Date.now();
            if (lastActivity && (now - lastActivity > SESSION_TIMEOUT)) {
                await this.clearSession();
                return { valid: false, reason: 'Session expired due to inactivity' };
            }

            // Update activity timestamp
            await chrome.storage.local.set({ lastActivity: now });

            return { valid: true, user, sessionToken };
        } catch (error) {
            console.error('Session validation error:', error);
            return { valid: false, reason: 'Session error' };
        }
    }

    async refreshSession() {
        const { user } = await chrome.storage.local.get(['user']);
        if (user) {
            await chrome.storage.local.set({ lastActivity: Date.now() });
            return true;
        }
        return false;
    }

    async clearSession() {
        await chrome.storage.local.remove(['user', 'lastActivity', 'sessionToken', 'sessionCreated']);
        await chrome.storage.session.clear();
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

    recordFailedAttempt() {
        this.failedAttempts++;
        if (this.failedAttempts >= MAX_FAILED_ATTEMPTS) {
            this.lockoutUntil = Date.now() + LOCKOUT_DURATION;
            return true;
        }
        return false;
    }

    getRemainingLockoutTime() {
        if (!this.lockoutUntil) return 0;
        return Math.max(0, this.lockoutUntil - Date.now());
    }
}

const sessionManager = new SessionManager();

// ============================================
// SECURE API CLIENT
// ============================================

class SecureAPIClient {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }

    async request(endpoint, options = {}) {
        const session = await sessionManager.validateSession();

        if (options.requiresAuth && !session.valid) {
            throw new Error(session.reason || 'Authentication required');
        }

        const headers = {
            ...options.headers
        };

        if (session.valid && session.user) {
            headers['x-user-id'] = session.user.id.toString();
            headers['x-timestamp'] = Date.now().toString();

            // Add request signature for integrity
            if (options.body && session.sessionToken) {
                try {
                    headers['x-signature'] = await SecureCrypto.signRequest(
                        JSON.parse(options.body),
                        session.sessionToken
                    );
                } catch (e) {
                    console.warn('Failed to sign request:', e);
                }
            }
        }

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

        try {
            const result = await secureClient.request(endpoint, {
                ...options,
                headers,
                signal: controller.signal
            });

            clearTimeout(timeoutId);
            return result;
        } catch (error) {
            clearTimeout(timeoutId);
            if (error.name === 'AbortError') {
                throw new Error('Request timeout');
            }
            throw error;
        }
    }

    async get(endpoint, requiresAuth = true) {
        return this.request(endpoint, { method: 'GET', requiresAuth });
    }

    async post(endpoint, data, requiresAuth = true) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data),
            requiresAuth
        });
    }

    async put(endpoint, data, requiresAuth = true) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data),
            requiresAuth
        });
    }

    async delete(endpoint, requiresAuth = true) {
        return this.request(endpoint, { method: 'DELETE', requiresAuth });
    }
}

const apiClient = new SecureAPIClient(currentApiBase);

const SESSION_TIMEOUT = 24 * 60 * 60 * 1000; // 24 hours
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes
const REQUEST_TIMEOUT = 10000; // 10 seconds

// ============================================
// MESSAGE HANDLERS
// ============================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message, sender).then(sendResponse).catch(error => {
        console.error('Message handler error:', error);
        sendResponse({ error: error.message });
    });
    return true; // Keep channel open for async response
});

async function handleMessage(message, sender) {
    const { type, data, url, username } = message;

    switch (type) {
        case 'DISCOVER_DEVICES':
            if (!data.email) return { error: 'Email required for discovery' };

            // Handle manual single IP verification
            if (data.singleIp) {
                discoveryService.verifyDirectIp(data.singleIp, data.email).then(device => {
                    if (device) {
                        chrome.runtime.sendMessage({ type: 'DEVICE_FOUND', device });
                    }
                    chrome.runtime.sendMessage({ type: 'DISCOVERY_FINISHED' });
                });
            } else {
                // Perform regular full scan
                discoveryService.scanForEmail(data.email, (device) => {
                    chrome.runtime.sendMessage({ type: 'DEVICE_FOUND', device });
                }).then(() => {
                    chrome.runtime.sendMessage({ type: 'DISCOVERY_FINISHED' });
                });
            }
            return { success: true, message: 'Scan started' };

        case 'SELECT_DEVICE':
            await updateApiBase(data.url);
            return { success: true };

        case 'GET_CREDENTIALS':
            return handleGetCredentials(url || message.url);

        case 'SAVE_CREDENTIALS':
            return handleSaveCredentials(data);

        case 'UPDATE_CREDENTIALS':
            return handleUpdateCredentials(data);

        case 'CHECK_EXISTING':
            return handleCheckExisting(url || message.url, username || message.username);

        case 'CHECK_SESSION':
            return handleCheckSession();

        case 'REFRESH_SESSION':
            const refreshed = await sessionManager.refreshSession();
            return { success: refreshed };

        case 'SECURITY_ALERT':
            return handleSecurityAlert();

        case 'LOGIN':
            return handleLogin(data);

        case 'LOGOUT':
            await sessionManager.clearSession();
            return { success: true };

        default:
            return { error: 'Unknown message type' };
    }
}

// ============================================
// CREDENTIAL HANDLERS
// ============================================

async function handleGetCredentials(url) {
    try {
        const session = await sessionManager.validateSession();
        if (!session.valid) {
            console.log('Session invalid:', session.reason);
            return { error: session.reason, credentials: [] };
        }

        const vaultItems = await apiClient.get('/vault');

        if (!url) {
            return { credentials: vaultItems };
        }

        // Domain matching for security
        const pageUrl = new URL(url);
        const domain = pageUrl.hostname.replace(/^www\./, '').toLowerCase();

        const matches = vaultItems.filter(item => {
            try {
                const serviceDomain = new URL(
                    item.service.startsWith('http') ? item.service : `https://${item.service}`
                ).hostname.replace(/^www\./, '').toLowerCase();

                return serviceDomain === domain ||
                    serviceDomain.endsWith('.' + domain) ||
                    domain.endsWith('.' + serviceDomain);
            } catch {
                const service = item.service.toLowerCase();
                return service.includes(domain) || domain.includes(service);
            }
        });

        // Resolve real passwords using POST so item IDs never appear in URLs or logs
        const enrichedMatches = await Promise.all(
            matches.map(async (item) => {
                try {
                    const pwData = await apiClient.post('/vault/reveal-password', { id: item.id }, true);
                    return { ...item, password: pwData.password };
                } catch (e) {
                    console.error(`Failed to reveal password for vault item:`, e.message);
                    return item; // fallback to masked if fetch fails
                }
            })
        );

        return { credentials: enrichedMatches };
    } catch (error) {
        console.error('Error fetching credentials:', error);
        return { error: error.message, credentials: [] };
    }
}

async function handleSaveCredentials(data) {
    try {
        const session = await sessionManager.validateSession();
        if (!session.valid) {
            return { success: false, error: session.reason };
        }

        if (!data.url || !data.password) {
            return { success: false, error: 'URL and password are required' };
        }

        const result = await apiClient.post('/vault', {
            service: data.url,
            username: data.username || '',
            password: data.password
        });

        // Verify result validity
        if (!result || typeof result !== 'object') {
            throw new Error('Invalid response from server');
        }

        return { success: true, id: result.id };
    } catch (error) {
        console.error('Error saving credentials:', error);
        console.error('Failed payload:', { url: data.url, username: data.username });
        return { success: false, error: error.message || 'Unknown save error' };
    }
}

async function handleUpdateCredentials(data) {
    try {
        const session = await sessionManager.validateSession();
        if (!session.valid) {
            return { success: false, error: session.reason };
        }

        if (!data.id) {
            return { success: false, error: 'Credential ID is required' };
        }

        await apiClient.put(`/vault/${data.id}`, {
            service: data.url,
            username: data.username || '',
            password: data.password
        });

        return { success: true };
    } catch (error) {
        console.error('Error updating credentials:', error);
        return { success: false, error: error.message };
    }
}

async function handleCheckExisting(url, username) {
    try {
        const session = await sessionManager.validateSession();
        if (!session.valid) {
            return { exists: false };
        }

        const { credentials } = await handleGetCredentials(url);

        if (!credentials || credentials.length === 0) {
            return { exists: false };
        }

        // Find exact username match
        const match = credentials.find(c =>
            c.username && c.username.toLowerCase() === (username || '').toLowerCase()
        );

        if (match) {
            return { exists: true, id: match.id };
        }

        // Return first match if no username specified
        if (!username && credentials.length > 0) {
            return { exists: true, id: credentials[0].id };
        }

        return { exists: false };
    } catch (error) {
        console.error('Error checking existing credentials:', error);
        return { exists: false };
    }
}

// ============================================
// SESSION HANDLERS
// ============================================

async function handleCheckSession() {
    const session = await sessionManager.validateSession();
    return {
        valid: session.valid,
        user: session.valid ? session.user : null,
        reason: session.reason
    };
}

async function handleLogin(data) {
    if (sessionManager.isLockedOut()) {
        const remaining = Math.ceil(sessionManager.getRemainingLockoutTime() / 60000);
        return {
            success: false,
            error: `Too many failed attempts. Try again in ${remaining} minutes.`
        };
    }

    try {
        const result = await secureClient.post('/users/extension/login', {
            email: data.email,
            otp: data.otp
        });

        // Normalize user object (extension login returns userId, session manager expects id)
        const user = {
            id: result.userId || result.id,
            username: result.username,
            ...result // keep other fields if any
        };

        // Create secure session
        await sessionManager.createSession(user);

        return { success: true, user: user };
    } catch (error) {
        console.error('Login error:', error);

        const locked = sessionManager.recordFailedAttempt();
        if (locked) {
            return {
                success: false,
                error: 'Too many failed attempts. Account locked for 15 minutes.'
            };
        }

        return { success: false, error: error.message || 'Connection failed' };
    }
}

async function handleSecurityAlert() {
    console.warn('Security alert triggered - clearing session');
    await sessionManager.clearSession();

    // Notify all tabs to clear cached credentials
    /* 
    try {
        const tabs = await chrome.tabs.query({});
        for (const tab of tabs) {
            try {
                await chrome.tabs.sendMessage(tab.id, { type: 'CLEAR_CACHE' });
            } catch {
                // Tab might not have content script
            }
        }
    } catch {
        // Ignore tab query errors
    }
    */

    return { success: true };
}

// ============================================
// SESSION AUTO-LOCK
// ============================================

// Check session validity periodically
chrome.alarms.create('sessionCheck', { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === 'sessionCheck') {
        const session = await sessionManager.validateSession();
        if (!session.valid && session.reason === 'Session expired due to inactivity') {
            // Notify popup if open
            try {
                await chrome.runtime.sendMessage({ type: 'SESSION_EXPIRED' });
            } catch {
                // Popup not open
            }
        }
    }
});

// Lock on browser idle
chrome.idle.onStateChanged.addListener(async (state) => {
    if (state === 'locked') {
        console.log('System locked - clearing session');
        await sessionManager.clearSession();
    }
});

// ============================================
// EXTENSION LIFECYCLE
// ============================================

chrome.runtime.onInstalled.addListener((details) => {
    if (details.reason === 'install') {
        console.log('Password Manager Extension installed');
    } else if (details.reason === 'update') {
        console.log('Password Manager Extension updated');
    }
});

chrome.runtime.onStartup.addListener(async () => {
    // Clear session on browser restart for security
    await sessionManager.clearSession();
});

// ============================================
// CONTEXT MENU (Right-click options)
// ============================================

chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: 'pm-save-credentials',
        title: 'Save credentials for this site',
        contexts: ['page', 'editable']
    });

    chrome.contextMenus.create({
        id: 'pm-fill-credentials',
        title: 'Fill credentials',
        contexts: ['editable']
    });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId === 'pm-save-credentials') {
        await chrome.tabs.sendMessage(tab.id, { type: 'OPEN_SAVE_DIALOG' });
    } else if (info.menuItemId === 'pm-fill-credentials') {
        await chrome.tabs.sendMessage(tab.id, { type: 'TRIGGER_AUTOFILL' });
    }
});
