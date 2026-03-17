/**
 * Discovery Service for Password Manager Backend
 * Scans the local network to find server instances holding a specific email.
 */

class DiscoveryService {
    constructor(port = 3001) {
        this.port = port;
        this.subnets = ['192.168.1', '192.168.0', '10.0.0'];
    }

    /**
     * Get candidate subnets based on local network interfaces
     */
    async getLocalSubnets() {
        if (!chrome.system || !chrome.system.network) {
            return this.subnets;
        }

        try {
            const interfaces = await new Promise(resolve => chrome.system.network.getNetworkInterfaces(resolve));
            const subnets = new Set();

            for (const iface of interfaces) {
                // Skip IPv6 and internal loopback
                if (iface.address.includes('.') && iface.address !== '127.0.0.1') {
                    const parts = iface.address.split('.');
                    if (parts.length === 4) {
                        // Handle standard Class C subnets (/24)
                        subnets.add(`${parts[0]}.${parts[1]}.${parts[2]}`);

                        // Also check common private network ranges in case of unusual subnet masks
                        if (parts[0] === '192' && parts[1] === '168') {
                            subnets.add('192.168.0');
                            subnets.add('192.168.1');
                        }
                        if (parts[0] === '10') {
                            subnets.add('10.0.0');
                            subnets.add('10.0.1');
                        }
                    }
                }
            }

            // Fallback to defaults if no subnets found
            if (subnets.size === 0) {
                this.subnets.forEach(s => subnets.add(s));
            }

            console.log('Detected local network subnets:', Array.from(subnets));
            return Array.from(subnets);
        } catch (e) {
            console.warn('Failed to get network interfaces:', e);
            return this.subnets;
        }
    }

    /**
     * Scan the network for a specific email
     * @param {string} email - Email to search for
     * @param {Function} onDeviceFound - Callback when a candidate is found
     */
    /**
     * Scan the network for a specific email
     */
    async scanForEmail(email, onDeviceFound) {
        const subnets = await this.getLocalSubnets();
        console.log(`[Discovery] 🚀 Starting Turbo Scan for ${email}`);

        // 1. Try "Last Known Good" and local commonalities first
        const locals = ['127.0.0.1', 'localhost'];

        // Check if we have a last successful IP in storage
        const storage = await chrome.storage.local.get(['lastSuccessfulIp']);
        if (storage.lastSuccessfulIp && !locals.includes(storage.lastSuccessfulIp)) {
            locals.unshift(storage.lastSuccessfulIp);
        }

        console.log(`[Discovery] Checking priority addresses: ${locals.join(', ')}`);
        const foundLocals = await Promise.all(locals.map(ip => this.checkDevice(ip, email, onDeviceFound)));
        if (foundLocals.some(d => d)) {
            console.log('[Discovery] Found device in priority scan.');
            return;
        }

        // 2. Full Network Scan with High Concurrency
        // Generate all candidate IPs
        const allCandidates = [];
        for (const subnet of subnets) {
            for (let i = 1; i < 255; i++) {
                const ip = `${subnet}.${i}`;
                if (!locals.includes(ip)) {
                    allCandidates.push(ip);
                }
            }
        }

        // Parallel processing with a 'worker pool' (Concurrency: 60)
        const concurrency = 60;
        let index = 0;
        let finished = false;

        const worker = async () => {
            while (index < allCandidates.length && !finished) {
                const ip = allCandidates[index++];
                const device = await this.checkDevice(ip, email, onDeviceFound);
                if (device) {
                    finished = true; // Stop other workers if we found a match
                    return;
                }
            }
        };

        const workers = Array(concurrency).fill(null).map(() => worker());
        await Promise.all(workers);

        console.log(`[Discovery] Turbo Scan completed for ${email}`);
    }

    async checkDevice(ip, email, onDeviceFound) {
        if (ip.endsWith('.0') || ip.endsWith('.255')) return null;

        const url = `http://${ip}:${this.port}/api/discovery/identify?email=${encodeURIComponent(email)}`;
        const controller = new AbortController();
        // Use shorter timeout for scanning (1.5s is plenty for a local ping)
        const timeoutId = setTimeout(() => controller.abort(), 1500);

        try {
            const response = await fetch(url, {
                signal: controller.signal,
                mode: 'cors',
                credentials: 'omit'
            });
            clearTimeout(timeoutId);

            if (response.ok) {
                const data = await response.json();
                if (data.emailMatch) {
                    const device = {
                        ip,
                        hostname: data.hostname,
                        url: `http://${ip}:${this.port}/api`
                    };

                    // Persist for next time
                    chrome.storage.local.set({ lastSuccessfulIp: ip });

                    console.log(`[Discovery] ✅ FOUND: ${data.hostname} (${ip})`);
                    if (onDeviceFound) onDeviceFound(device);
                    return device;
                }
            }
        } catch (e) {
            // Silence noise during large scans
        } finally {
            clearTimeout(timeoutId);
        }
        return null;
    }

    /**
     * Directly verify a manually entered IP
     */
    async verifyDirectIp(ip, email) {
        return this.checkDevice(ip, email, null);
    }
}

// Export
if (typeof globalThis !== 'undefined') {
    globalThis.DiscoveryService = DiscoveryService;
}
