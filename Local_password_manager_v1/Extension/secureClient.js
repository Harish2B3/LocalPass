/**
 * Secure Communication Client for Extension
 * Handles:
 * 1. Handshake with backend (RSA-OAEP)
 * 2. Session key management (AES-GCM)
 * 3. Automatic payload encryption/decryption
 */

class SecureClient {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
        this.transportKey = null;
        this.sessionToken = null;
        this.handshakeInProgress = null;
    }

    /**
     * Initialize secure tunnel with backend
     */
    async initialize() {
        if (this.handshakeInProgress) return this.handshakeInProgress;

        this.handshakeInProgress = (async () => {
            try {
                // 1. Get Server Public Key
                const pkResponse = await fetch(`${this.baseUrl}/security/public-key`);
                const { publicKey: pemPK } = await pkResponse.json();
                const serverPublicKey = await SecureCrypto.importPublicKey(pemPK);

                // 2. Generate random Session Token (for tunnel identification)
                this.sessionToken = SecureCrypto.arrayToBase64(crypto.getRandomValues(new Uint8Array(16)));

                // 3. Generate random Transport Key (AES-256)
                this.transportKey = await SecureCrypto.generateTransportKey();
                const rawKey = await SecureCrypto.exportKey(this.transportKey);

                // 4. Encrypt Transport Key with Server Public Key
                const encryptedKey = await SecureCrypto.encryptWithRSA(rawKey, serverPublicKey);

                // 5. Handshake
                const hsResponse = await fetch(`${this.baseUrl}/security/handshake`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        sessionToken: this.sessionToken,
                        encryptedKey: encryptedKey
                    })
                });

                if (!hsResponse.ok) throw new Error('Handshake failed on server');

                console.log('Secure tunnel established');
                return true;
            } catch (error) {
                console.error('Secure tunnel initialization failed:', error);
                this.transportKey = null;
                throw error;
            } finally {
                this.handshakeInProgress = null;
            }
        })();

        return this.handshakeInProgress;
    }

    /**
     * Encrypted Request wrapper
     */
    async request(endpoint, options = {}) {
        if (!this.transportKey) {
            await this.initialize();
        }

        const headers = {
            ...options.headers,
            'x-session-id': this.sessionToken,
            'Content-Type': 'application/json'
        };

        let body = options.body;
        if (body && typeof body === 'string' && options.method !== 'GET') {
            // Encrypt the payload
            const encrypted = await SecureCrypto.encryptData(body, this.transportKey);
            body = JSON.stringify({
                encryptedData: true,
                iv: encrypted.iv,
                data: encrypted.data,
                tag: encrypted.tag
            });
        }

        const response = await fetch(`${this.baseUrl}${endpoint}`, {
            ...options,
            headers,
            body,
            signal: options.signal
        });

        const contentType = response.headers.get('content-type');
        let data;
        if (contentType && contentType.includes('application/json')) {
            data = await response.json();
        } else {
            data = await response.text();
        }

        if (!response.ok) {
            throw new Error(data.error || `HTTP ${response.status}`);
        }

        // Decrypt the response if it's encrypted
        if (data && data.encrypted) {
            const decrypted = await SecureCrypto.decryptData(
                { iv: data.iv, data: data.data, tag: data.tag },
                this.transportKey
            );
            return JSON.parse(decrypted);
        }

        return data;
    }

    async get(endpoint) {
        return this.request(endpoint, { method: 'GET' });
    }

    async post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }

    async put(endpoint, data) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }

    async delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }
}
