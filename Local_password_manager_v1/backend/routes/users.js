const express = require('express');
const router = express.Router();
const db = require('../database');
const {
    encrypt,
    decrypt,
    hashPassword,
    verifyPassword,
    generateSalt
} = require('../encryption');
const CryptoJS = require('crypto-js'); // Kept for legacy migration
const { logAction } = require('../middleware/audit');

// Helper for migrating old 1000-iteration passwords
const verifyLegacyPassword = (password, salt, storedHash) => {
    try {
        const hash = CryptoJS.PBKDF2(password, salt, {
            keySize: 512 / 32,
            iterations: 1000
        }).toString(CryptoJS.enc.Hex);
        return hash === storedHash;
    } catch { return false; }
};

// GET all users (only username and id)
router.get('/', (req, res) => {
    db.all('SELECT id, username FROM users', [], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows);
    });
});

// POST /register a new user
router.post('/register', (req, res) => {
    const { username, email, password, question1, answer1, question2, answer2 } = req.body;
    if (!username || !email || !password || !question1 || !answer1 || !question2 || !answer2) {
        return res.status(400).json({ error: 'All fields, including email and security questions, are required' });
    }

    // Check if username already exists
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (row) {
            return res.status(409).json({ error: 'Username already exists' });
        }

        // Hash password and encrypt answers
        const salt = generateSalt();
        const hash = hashPassword(password, salt);

        const encryptedQuestion1 = encrypt(question1);
        const encryptedQuestion2 = encrypt(question2);
        const encryptedAnswer1 = encrypt(answer1);
        const encryptedAnswer2 = encrypt(answer2);

        const sql = `INSERT INTO users (username, email, password_hash, password_salt, question1_iv, question1_content, answer1_iv, answer1_content, question2_iv, question2_content, answer2_iv, answer2_content) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        const params = [
            username, email, hash, salt,
            encryptedQuestion1.iv, encryptedQuestion1.content,
            encryptedAnswer1.iv, encryptedAnswer1.content,
            encryptedQuestion2.iv, encryptedQuestion2.content,
            encryptedAnswer2.iv, encryptedAnswer2.content
        ];

        db.run(sql, params, function (err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            const newUserId = this.lastID;
            logAction(req, 'REGISTER', `New user registered: ${username}`, newUserId);
            res.status(201).json({ id: newUserId, username: username });
        });
    });
});

// POST /login
router.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // 1. Try secure verification (100,000 iterations)
        const isValid = verifyPassword(password, user.password_salt, user.password_hash);

        if (isValid) {
            logAction(req, 'LOGIN', 'User logged in successfully', user.id);
            return res.status(200).json({ id: user.id, username: user.username });
        }

        // 2. Try legacy verification (1000 iterations) - Auto Migrate
        const isLegacyValid = verifyLegacyPassword(password, user.password_salt, user.password_hash);

        if (isLegacyValid) {
            console.log(`Migrating user ${user.username} to secure hashing...`);

            // Generate new secure hash
            const newSalt = generateSalt();
            const newHash = hashPassword(password, newSalt);

            // Update DB asynchronously
            db.run('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?',
                [newHash, newSalt, user.id],
                (err) => {
                    if (err) console.error('Migration failed:', err);
                    else console.log('Migration successful.');
                }
            );

            return res.status(200).json({ id: user.id, username: user.username });
        }

        logAction(req, 'LOGIN_FAILED', `Failed login attempt for username: ${username}`, null); // Log authentication failure (optional, might spam DB)
        res.status(401).json({ error: 'Invalid credentials' });
    });
});

// POST /change-password
router.post('/change-password', (req, res) => {
    const { userId, currentPassword, newPassword } = req.body;

    if (!userId || !currentPassword || !newPassword) {
        return res.status(400).json({ error: 'User ID, current password, and new password are required' });
    }

    db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Verify current password
        const isValid = verifyPassword(currentPassword, user.password_salt, user.password_hash);

        // Also check legacy if not secure
        const isLegacyValid = !isValid && verifyLegacyPassword(currentPassword, user.password_salt, user.password_hash);

        if (!isValid && !isLegacyValid) {
            return res.status(401).json({ error: 'Incorrect current password' });
        }

        // Hash new password
        const salt = generateSalt();
        const hash = hashPassword(newPassword, salt);

        db.run('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?', [hash, salt, userId], function (err) {
            if (err) return res.status(500).json({ error: 'Failed to update password' });

            logAction(req, 'CHANGE_PASSWORD', 'User changed their password', userId);
            res.json({ success: true, message: 'Password updated successfully' });
        });
    });
});

// DELETE a user and all their data
router.delete('/:id', (req, res) => {
    const { id } = req.params;

    // Use serialize to ensure sequential execution (transaction-like)
    db.serialize(() => {
        // Since we have ON DELETE CASCADE in the schema, we only need to delete the user.
        // But we keep the manual deletion just in case foreign keys are not enabled globally.

        // 1. Delete all vault items
        db.run('DELETE FROM vault WHERE user_id = ?', id, (err) => {
            if (err) console.error('Error deleting vault items:', err.message);
        });

        // 2. Delete all notes
        db.run('DELETE FROM notes WHERE user_id = ?', id, (err) => {
            if (err) console.error('Error deleting notes:', err.message);
        });

        // 3. Delete all cards
        db.run('DELETE FROM cards WHERE user_id = ?', id, (err) => {
            if (err) console.error('Error deleting cards:', err.message);
        });

        // 4. Finally delete the user
        db.run('DELETE FROM users WHERE id = ?', id, function (err) {
            if (err) {
                return res.status(500).json({ error: 'Failed to delete user account.' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'User not found.' });
            }
            res.status(200).json({ message: 'User account and all associated data deleted successfully.' });
        });
    });
});

// --- FORGOT PASSWORD FLOW ---

// Get security questions for a user
router.post('/forgot-password/questions', (req, res) => {
    const { username } = req.body;
    if (!username) {
        return res.status(400).json({ error: 'Username is required' });
    }
    db.get('SELECT question1_iv, question1_content, question2_iv, question2_content FROM users WHERE username = ?', [username], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error.' });
        if (!row || !row.question1_iv) return res.status(404).json({ error: 'User not found or security questions not set up.' });

        const question1 = decrypt({ iv: row.question1_iv, content: row.question1_content });
        const question2 = decrypt({ iv: row.question2_iv, content: row.question2_content });

        res.json({ question1, question2 });
    });
});

// Verify security answers
router.post('/forgot-password/verify-answers', (req, res) => {
    const { username, answer1, answer2 } = req.body;
    if (!username || !answer1 || !answer2) {
        return res.status(400).json({ error: 'Username and both answers are required.' });
    }
    db.get('SELECT answer1_iv, answer1_content, answer2_iv, answer2_content FROM users WHERE username = ?', [username], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error.' });
        if (!row) return res.status(404).json({ error: 'User not found.' });

        const decryptedAnswer1 = decrypt({ iv: row.answer1_iv, content: row.answer1_content });
        const decryptedAnswer2 = decrypt({ iv: row.answer2_iv, content: row.answer2_content });

        const isAnswer1Correct = decryptedAnswer1.trim().toLowerCase() === answer1.trim().toLowerCase();
        const isAnswer2Correct = decryptedAnswer2.trim().toLowerCase() === answer2.trim().toLowerCase();

        if (isAnswer1Correct && isAnswer2Correct) {
            res.json({ success: true, message: 'Answers verified.' });
        } else {
            res.status(401).json({ error: 'One or more answers are incorrect.' });
        }
    });
});

// Reset password after successful verification
router.post('/forgot-password/reset', (req, res) => {
    const { username, newPassword } = req.body;
    if (!username || !newPassword) {
        return res.status(400).json({ error: 'Username and new password are required.' });
    }

    const salt = generateSalt();
    const hash = hashPassword(newPassword, salt);

    db.run('UPDATE users SET password_hash = ?, password_salt = ? WHERE username = ?', [hash, salt, username], function (err) {
        if (err) return res.status(500).json({ error: 'Failed to update password.' });
        if (this.changes === 0) return res.status(404).json({ error: 'User not found during password update.' });

        // Fetch user ID to log action
        db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
            if (row) logAction(req, 'RESET_PASSWORD', 'Password reset performed', row.id);
        });

        res.json({ message: 'Password has been reset successfully.' });
    });
});

// --- EXTENSION SUPPORT ---

// Update Extension Settings (Enable/Disable, Set Email)
router.post('/extension/settings', (req, res) => {
    const { userId, enabled, email } = req.body;

    if (!userId) {
        return res.status(400).json({ error: 'User ID is required' });
    }

    if (!enabled) {
        db.run('UPDATE users SET extension_enabled = 0 WHERE id = ?', [userId], function (err) {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ success: true, message: 'Extension access disabled.' });
        });
        return;
    }

    if (!email) {
        return res.status(400).json({ error: 'Email is required to enable extension access.' });
    }

    // Update both enabled status and ensure email is set (in case it wasn't during registration)
    db.run('UPDATE users SET extension_enabled = 1, email = ? WHERE id = ?', [email, userId], function (err) {
        if (err) return res.status(500).json({ error: 'Failed to update extension settings.' });

        logAction(req, 'UPDATE_EXTENSION_SETTINGS', 'Extension access enabled for ' + email, userId);
        res.json({ success: true, message: 'Extension settings updated successfully.' });
    });
});

// --- EXTENSION OTP FLOW ---

// Get or Generate OTP for Extension (for main app UI)
router.get('/extension/otp', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) return res.status(400).json({ error: 'User ID required' });

    db.get('SELECT otp_code, otp_expiry FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        const now = new Date();
        if (user && user.otp_code && user.otp_expiry && new Date(user.otp_expiry) > now) {
            return res.json({ otp: user.otp_code, expiry: user.otp_expiry });
        }

        // Generate new OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expiry = new Date(now.getTime() + 10 * 60 * 1000); // 10 minutes

        db.run('UPDATE users SET otp_code = ?, otp_expiry = ? WHERE id = ?', [otp, expiry.toISOString(), userId], (err) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            res.json({ otp, expiry: expiry.toISOString() });
        });
    });
});

// Extension Login with Email and OTP
router.post('/extension/login', (req, res) => {
    const { email, otp } = req.body;

    console.log(`[EXTENSION LOGIN] Body received:`, JSON.stringify(req.body));
    console.log(`[EXTENSION LOGIN] email="${email}" otp="${otp}"`);

    if (!email || !otp) {
        console.warn(`[EXTENSION LOGIN] Missing fields. email=${!!email}, otp=${!!otp}`);
        return res.status(400).json({ error: 'Email and OTP required.' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const now = new Date();
        if (!user.otp_code || !user.otp_expiry || new Date(user.otp_expiry) < now) {
            return res.status(401).json({ error: 'OTP expired. Please generate a new one in the main app.' });
        }

        if (user.otp_code !== otp) {
            return res.status(401).json({ error: 'Invalid OTP.' });
        }

        // Clear OTP after successful login for security
        db.run('UPDATE users SET otp_code = NULL, otp_expiry = NULL WHERE id = ?', [user.id]);

        logAction(req, 'EXTENSION_LOGIN', 'Login via extension with OTP', user.id);

        return res.json({
            success: true,
            userId: user.id,
            username: user.username
        });
    });
});

// Get Extension Status for User
router.get('/extension/status', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) return res.status(400).json({ error: 'User ID required' });

    db.get('SELECT extension_enabled, email FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!row) return res.status(404).json({ error: 'User not found' });

        res.json({
            enabled: !!row.extension_enabled,
            email: row.email
        });
    });
});
module.exports = router;