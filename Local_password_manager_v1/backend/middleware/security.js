/**
 * Security Middleware for Password Manager Backend
 * Provides:
 * - Rate limiting per user/IP
 * - Request signature verification
 * - Replay attack protection
 * - Request logging for audit
 */

const crypto = require('crypto');

// ============================================
// RATE LIMITER
// ============================================

class RateLimiter {
    constructor(options = {}) {
        this.windowMs = options.windowMs || 15 * 60 * 1000; // 15 minutes
        this.maxRequests = options.maxRequests || 100;
        this.requests = new Map();

        // Cleanup old entries periodically
        setInterval(() => this.cleanup(), this.windowMs);
    }

    isAllowed(key) {
        const now = Date.now();
        const record = this.requests.get(key);

        if (!record) {
            this.requests.set(key, { count: 1, firstRequest: now });
            return true;
        }

        // Reset if window has passed
        if (now - record.firstRequest > this.windowMs) {
            this.requests.set(key, { count: 1, firstRequest: now });
            return true;
        }

        // Increment and check
        record.count++;
        return record.count <= this.maxRequests;
    }

    getRemainingRequests(key) {
        const record = this.requests.get(key);
        if (!record) return this.maxRequests;
        return Math.max(0, this.maxRequests - record.count);
    }

    cleanup() {
        const now = Date.now();
        for (const [key, record] of this.requests.entries()) {
            if (now - record.firstRequest > this.windowMs) {
                this.requests.delete(key);
            }
        }
    }
}

// Global rate limiters
const globalLimiter = new RateLimiter({ windowMs: 15 * 60 * 1000, maxRequests: 100 });
const loginLimiter = new RateLimiter({ windowMs: 15 * 60 * 1000, maxRequests: 10 });
const vaultLimiter = new RateLimiter({ windowMs: 60 * 1000, maxRequests: 30 });

// ============================================
// RATE LIMIT MIDDLEWARE
// ============================================

const rateLimitMiddleware = (limiter, keyExtractor = (req) => req.ip) => {
    return (req, res, next) => {
        const key = keyExtractor(req);

        if (!limiter.isAllowed(key)) {
            console.warn(`Rate limit exceeded for: ${key}`);
            return res.status(429).json({
                error: 'Too many requests. Please try again later.',
                retryAfter: Math.ceil(limiter.windowMs / 1000)
            });
        }

        // Add rate limit headers
        res.set('X-RateLimit-Remaining', limiter.getRemainingRequests(key));
        res.set('X-RateLimit-Reset', Date.now() + limiter.windowMs);

        next();
    };
};

// ============================================
// SIGNATURE VERIFICATION
// ============================================

// Store used nonces to prevent replay attacks (with TTL cleanup)
const usedNonces = new Map();
const NONCE_TTL = 5 * 60 * 1000; // 5 minutes

// Cleanup expired nonces periodically
setInterval(() => {
    const now = Date.now();
    for (const [nonce, timestamp] of usedNonces.entries()) {
        if (now - timestamp > NONCE_TTL) {
            usedNonces.delete(nonce);
        }
    }
}, 60 * 1000); // Every minute

const verifySignature = (req, res, next) => {
    const signature = req.headers['x-signature'];
    const timestamp = parseInt(req.headers['x-timestamp']);
    const userId = req.headers['x-user-id'];

    // Skip signature verification for development (remove in production)
    if (process.env.NODE_ENV !== 'production') {
        return next();
    }

    // Validate required headers
    if (!signature || !timestamp) {
        return res.status(401).json({ error: 'Missing security headers' });
    }

    // Check timestamp is within acceptable range (5 minutes)
    const now = Date.now();
    if (Math.abs(now - timestamp) > NONCE_TTL) {
        return res.status(401).json({ error: 'Request expired' });
    }

    // Check for replay attack
    const nonce = `${userId}_${timestamp}_${signature.substring(0, 16)}`;
    if (usedNonces.has(nonce)) {
        console.warn(`Replay attack detected for user: ${userId}`);
        return res.status(401).json({ error: 'Duplicate request detected' });
    }
    usedNonces.set(nonce, now);

    // TODO: In production, verify HMAC signature against stored session token
    // For now, just validate the headers exist

    next();
};

// ============================================
// REQUEST LOGGING (AUDIT)
// ============================================

const requestLogger = (req, res, next) => {
    const startTime = Date.now();
    const userId = req.headers['x-user-id'] || 'anonymous';

    // Log request
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - User: ${userId}`);

    // Capture response
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        const logLevel = res.statusCode >= 400 ? 'warn' : 'info';

        console[logLevel](
            `[${new Date().toISOString()}] ${req.method} ${req.path} - ` +
            `Status: ${res.statusCode} - Duration: ${duration}ms - User: ${userId}`
        );
    });

    next();
};

// ============================================
// INPUT SANITIZATION
// ============================================

const sanitizeInput = (req, res, next) => {
    // Sanitize body
    if (req.body && typeof req.body === 'object') {
        sanitizeObject(req.body);
    }

    // Sanitize query params
    if (req.query && typeof req.query === 'object') {
        sanitizeObject(req.query);
    }

    next();
};

function sanitizeObject(obj) {
    for (const key of Object.keys(obj)) {
        if (typeof obj[key] === 'string') {
            // Remove potential XSS vectors (basic sanitization)
            obj[key] = obj[key]
                .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
                .replace(/javascript:/gi, '')
                .replace(/on\w+\s*=/gi, '');
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
            sanitizeObject(obj[key]);
        }
    }
}

// ============================================
// CORS CONFIGURATION
// ============================================

const corsOptions = {
    origin: (origin, callback) => {
        // Allow requests with no origin or from Chrome extensions
        if (!origin || origin.startsWith('chrome-extension://')) {
            return callback(null, true);
        }

        // Whitelist localhost for development
        const allowedOrigins = [
            'http://localhost:5173',
            'http://localhost:3000',
            'http://localhost:3001'
        ];

        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            console.warn(`CORS blocked origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
        'Content-Type',
        'x-user-id',
        'x-signature',
        'x-timestamp',
        'x-session-id',
        'Authorization'
    ],
    exposedHeaders: [
        'X-RateLimit-Remaining',
        'X-RateLimit-Reset'
    ]
};

// ============================================
// SECURITY HEADERS
// ============================================

const securityHeaders = (req, res, next) => {
    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY');

    // Prevent MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // Enable XSS filter
    res.setHeader('X-XSS-Protection', '1; mode=block');

    // Referrer policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    // Allow Private Network Access (CORS-RFC1918)
    // This is crucial for Chrome extensions connecting to local IPs
    if (req.headers['access-control-request-private-network']) {
        res.setHeader('Access-Control-Allow-Private-Network', 'true');
    }

    // Explicitly handle all OPTIONS preflight requests more robustly
    if (req.method === 'OPTIONS') {
        // Essential headers for PNA and standard CORS
        res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || 'Content-Type, x-user-id, x-signature, x-timestamp, x-session-id, Authorization');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Max-Age', '86400');

        if (req.headers['access-control-request-private-network']) {
            res.setHeader('Access-Control-Allow-Private-Network', 'true');
        }

        return res.sendStatus(204);
    }

    // Cache control for sensitive data
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    next();
};

// ============================================
// USER AUTHENTICATION CHECK
// ============================================

const requireAuth = (req, res, next) => {
    const userId = req.headers['x-user-id'];

    if (!userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    // Attach user ID to request for convenience
    req.userId = parseInt(userId);

    if (isNaN(req.userId)) {
        return res.status(401).json({ error: 'Invalid user ID' });
    }

    next();
};

// ============================================
// EXPORTS
// ============================================

module.exports = {
    // Rate limiters
    globalLimiter,
    loginLimiter,
    vaultLimiter,
    rateLimitMiddleware,

    // Security middleware
    verifySignature,
    requestLogger,
    sanitizeInput,
    securityHeaders,
    requireAuth,

    // CORS config
    corsOptions
};
