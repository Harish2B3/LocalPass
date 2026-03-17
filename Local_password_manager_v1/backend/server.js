const express = require('express');
const cors = require('cors');

// Import database (initializes connection and creates tables)
const db = require('./database');

// Import security middleware
const {
  rateLimitMiddleware,
  globalLimiter,
  loginLimiter,
  vaultLimiter,
  requestLogger,
  sanitizeInput,
  securityHeaders,
  corsOptions
} = require('./middleware/security');

// Import routes
const vaultRoutes = require('./routes/vault');
const notesRoutes = require('./routes/notes');
const cardsRoutes = require('./routes/cards');
const usersRoutes = require('./routes/users');
const backupRoutes = require('./routes/backup');
const logsRoutes = require('./routes/logs');

const {
  decryptRequest,
  encryptResponse,
  setupHandshakeRoutes
} = require('./middleware/secureTunnel');

const app = express();
const PORT = process.env.PORT || 3001;

// ============================================
// SECURITY MIDDLEWARE (Order matters!)
// ============================================

// 1. Security headers on all responses
app.use(securityHeaders);

// 2. CORS configuration
app.use(cors(corsOptions));

// 3. Request parsing with size limits
app.use(express.json({ limit: '10mb' }));

// 4. Secure Tunnel Handshake (must be before decryption middleware)
setupHandshakeRoutes(app);

// ============================================
// PUBLIC DISCOVERY ENDPOINTS
// (Must be BEFORE decryption middleware)
// ============================================

app.get('/api/discovery/ping', (req, res) => {
  console.log(`[Discovery] Ping received from ${req.ip}`);
  res.json({ name: 'PassManager', version: '2.0.0', hostname: require('os').hostname() });
});

app.get('/api/discovery/identify', (req, res) => {
  const email = req.query.email;
  console.log(`[Discovery] Identity check for ${email} from ${req.ip}`);
  if (!email) return res.status(400).json({ error: 'Email required' });

  // Case-insensitive email search
  db.get('SELECT id FROM users WHERE LOWER(email) = LOWER(?)', [email], (err, row) => {
    if (err) {
      console.error(`[Discovery] DB Error: ${err.message}`);
      return res.status(500).json({ error: 'DB Error' });
    }

    const userFound = !!row;
    console.log(`[Discovery] Search for ${email} - Result: ${userFound ? '✅ FOUND' : '❌ NOT FOUND'}`);

    res.json({
      found: userFound,
      hostname: require('os').hostname(),
      emailMatch: userFound
    });
  });
});

// 5. Message-Level Encryption (Decrypt requests, Encrypt responses)
app.use(decryptRequest);
app.use(encryptResponse);

// 6. Input sanitization
app.use(sanitizeInput);

// 7. Request logging for audit
app.use(requestLogger);

// 6. Global rate limiting
app.use('/api/', rateLimitMiddleware(globalLimiter, (req) => {
  // Use user ID if available, otherwise IP
  return req.headers['x-user-id'] || req.ip;
}));

// ============================================
// ROUTE-SPECIFIC RATE LIMITING
// ============================================

// Stricter rate limiting on login endpoint
app.use('/api/users/login', rateLimitMiddleware(loginLimiter, (req) => req.ip));
app.use('/api/users/register', rateLimitMiddleware(loginLimiter, (req) => req.ip));

// Rate limiting on vault operations
app.use('/api/vault', rateLimitMiddleware(vaultLimiter, (req) => {
  return req.headers['x-user-id'] || req.ip;
}));

// ============================================
// API ROUTES
// ============================================

app.use('/api/users', usersRoutes);
app.use('/api/vault', vaultRoutes);
app.use('/api/notes', notesRoutes);
app.use('/api/cards', cardsRoutes);
app.use('/api/backup', backupRoutes);
app.use('/api/logs', logsRoutes);

// ============================================
// HEALTH CHECK & INFO
// ============================================

const serverInfoHandler = (req, res) => {
  db.get("SELECT value FROM system_config WHERE key = 'server_id'", (err, row) => {
    const serverId = row ? row.value : 'initializing...';
    res.json({
      name: 'PassManager Backend',
      version: '2.0.0',
      status: 'running',
      server_id: serverId,
      security: {
        rateLimiting: true,
        encryption: 'AES-256-GCM',
        headers: true
      }
    });
  });
};

app.get('/', serverInfoHandler);
app.get('/api', serverInfoHandler);
app.get('/api/', serverInfoHandler);

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Handled in public section above

// ============================================
// ERROR HANDLING
// ============================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(`[ERROR] ${new Date().toISOString()}:`, err);

  // Don't leak error details in production
  const message = process.env.NODE_ENV === 'production'
    ? 'Internal server error'
    : err.message;

  res.status(err.status || 500).json({ error: message });
});

// ============================================
// SERVER STARTUP
// ============================================

app.listen(PORT, '0.0.0.0', () => {
  const os = require('os');
  const networkInterfaces = os.networkInterfaces();
  const addresses = [];

  Object.keys(networkInterfaces).forEach((ifname) => {
    networkInterfaces[ifname].forEach((iface) => {
      if ('IPv4' === iface.family && !iface.internal) {
        addresses.push({ name: ifname, address: iface.address });
      }
    });
  });

  console.log('================================================');
  console.log(`  PassManager Backend v2.0 - Secure Edition`);
  console.log('================================================');
  console.log(`  Local:     http://localhost:${PORT}`);

  if (addresses.length > 0) {
    addresses.forEach(addr => {
      console.log(`  Network:   http://${addr.address}:${PORT} (${addr.name})`);
    });
  } else {
    console.log(`  Network:   No external IPv4 interfaces found`);
  }

  console.log(`  Security:  Rate limiting & PNA headers enabled`);
  console.log(`  Encryption: AES-256-GCM`);
  console.log('================================================');
  console.log(`  Status:    Listening on ALL networks (0.0.0.0)`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Closing server...');
  db.close(() => {
    console.log('Database connection closed.');
    process.exit(0);
  });
});