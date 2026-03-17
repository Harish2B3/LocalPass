const crypto = require('crypto');

/**
 * Secure Tunnel Middleware
 * Implements Message-Level Encryption (MLE) between Extension and Backend
 * 1. RSA Public Key Exchange
 * 2. Encrypted Session Key (AES-256) Handshake
 * 3. AES-GCM Encryption for all API payloads
 */

// Generate RSA Key Pair for the server
// In a real production app, you might want to persist these or use a cert
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
});

// In-memory store for session keys (Transport Keys)
// Map: sessionToken -> aesKey (Buffer)
const transportKeys = new Map();

/**
 * Middleware to decrypt incoming requests
 */
const decryptRequest = (req, res, next) => {
    const sessionToken = req.headers['x-session-id'];
    const encryptedBody = req.body.encryptedData;

    if (!encryptedBody) {
        return next(); // Not an encrypted request
    }

    if (!sessionToken || !transportKeys.has(sessionToken)) {
        return res.status(401).json({ error: 'Secure session not initialized' });
    }

    try {
        const { key } = transportKeys.get(sessionToken);
        const { iv, data, tag } = req.body;

        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            key,
            Buffer.from(iv, 'base64')
        );
        decipher.setAuthTag(Buffer.from(tag, 'base64'));

        let decrypted = decipher.update(data, 'base64', 'utf8');
        decrypted += decipher.final('utf8');

        req.body = JSON.parse(decrypted);
        req.isEncrypted = true;
        next();
    } catch (error) {
        console.error('Decryption failed:', error.message);
        res.status(400).json({ error: 'Failed to decrypt request' });
    }
};

/**
 * Helper to encrypt responses
 */
const encryptResponse = (req, res, next) => {
    const sessionToken = req.headers['x-session-id'];
    const originalJson = res.json;

    // Only encrypt if the request was encrypted or if it's a secure session
    if (!sessionToken || !transportKeys.has(sessionToken)) {
        return next();
    }

    res.json = function (data) {
        try {
            const { key } = transportKeys.get(sessionToken);
            const iv = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

            let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'base64');
            encrypted += cipher.final('base64');
            const tag = cipher.getAuthTag();

            return originalJson.call(this, {
                encrypted: true,
                iv: iv.toString('base64'),
                data: encrypted,
                tag: tag.toString('base64')
            });
        } catch (error) {
            console.error('Encryption failed:', error.message);
            return originalJson.call(this, { error: 'Failed to encrypt response' });
        }
    };

    next();
};

/**
 * Handshake Routes
 */
const setupHandshakeRoutes = (app) => {
    // Get Server Public Key
    app.get('/api/security/public-key', (req, res) => {
        res.json({ publicKey });
    });

    // Handshake: Receive encrypted AES key
    app.post('/api/security/handshake', (req, res) => {
        const { encryptedKey, sessionToken } = req.body;

        if (!encryptedKey || !sessionToken) {
            return res.status(400).json({ error: 'Missing handshake data' });
        }

        try {
            // Decrypt the AES key using Server's Private Key
            const aesKey = crypto.privateDecrypt(
                {
                    key: privateKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: 'sha256'
                },
                Buffer.from(encryptedKey, 'base64')
            );

            // Store the transport key for this session
            transportKeys.set(sessionToken, {
                key: aesKey,
                created: Date.now()
            });

            console.log(`[SECURITY] Handshake successful for session: ${sessionToken.substring(0, 8)}...`);
            res.json({ success: true });
        } catch (error) {
            console.error('Handshake failed:', error.message);
            res.status(400).json({ error: 'Handshake failed' });
        }
    });
};

// Cleanup old transport keys periodically
setInterval(() => {
    const now = Date.now();
    const TTL = 24 * 60 * 60 * 1000; // 24 hours
    for (const [token, data] of transportKeys.entries()) {
        if (now - data.created > TTL) {
            transportKeys.delete(token);
        }
    }
}, 60 * 60 * 1000);

module.exports = {
    decryptRequest,
    encryptResponse,
    setupHandshakeRoutes
};
