
const express = require('express');
const router = express.Router();
const db = require('../database');
const CryptoJS = require('crypto-js');
const { encrypt, decrypt } = require('../encryption');

// Helper function for password hashing
const hashPassword = (password) => {
    const salt = CryptoJS.lib.WordArray.random(128 / 8).toString(CryptoJS.enc.Hex);
    const hash = CryptoJS.PBKDF2(password, salt, {
        keySize: 512 / 32,
        iterations: 1000
    }).toString(CryptoJS.enc.Hex);
    return { salt, hash };
};

// Helper function to verify password
const verifyPassword = (password, salt, storedHash) => {
    const hash = CryptoJS.PBKDF2(password, salt, {
        keySize: 512 / 32,
        iterations: 1000
    }).toString(CryptoJS.enc.Hex);
    return hash === storedHash;
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
    const { username, password, question1, answer1, question2, answer2 } = req.body;
    if (!username || !password || !question1 || !answer1 || !question2 || !answer2) {
        return res.status(400).json({ error: 'All fields, including security questions and answers, are required' });
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
        const { salt, hash } = hashPassword(password);
        const encryptedAnswer1 = encrypt(answer1);
        const encryptedAnswer2 = encrypt(answer2);
        
        const sql = `INSERT INTO users (username, password_hash, password_salt, question1, answer1_iv, answer1_content, question2, answer2_iv, answer2_content) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        const params = [
            username, hash, salt, 
            question1, encryptedAnswer1.iv, encryptedAnswer1.content,
            question2, encryptedAnswer2.iv, encryptedAnswer2.content
        ];

        db.run(sql, params, function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.status(201).json({ id: this.lastID, username: username });
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

        const isValid = verifyPassword(password, user.password_salt, user.password_hash);
        if (isValid) {
            res.status(200).json({ id: user.id, username: user.username });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

// DELETE a user and all their data
router.delete('/:id', (req, res) => {
    const { id } = req.params;
    // The ON DELETE CASCADE constraint on the foreign keys in the vault, notes, 
    // and cards tables will automatically delete all associated data.
    db.run('DELETE FROM users WHERE id = ?', id, function(err) {
        if (err) {
            return res.status(500).json({ error: 'Failed to delete user account.' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }
        res.status(200).json({ message: 'User account and all associated data deleted successfully.' });
    });
});

// --- FORGOT PASSWORD FLOW ---

// Get security questions for a user
router.post('/forgot-password/questions', (req, res) => {
    const { username } = req.body;
    if (!username) {
        return res.status(400).json({ error: 'Username is required' });
    }
    db.get('SELECT question1, question2 FROM users WHERE username = ?', [username], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error while fetching questions.' });
        if (!row || !row.question1) return res.status(404).json({ error: 'User not found or security questions not set up.' });
        res.json(row);
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

    const { salt, hash } = hashPassword(newPassword);
    db.run('UPDATE users SET password_hash = ?, password_salt = ? WHERE username = ?', [hash, salt, username], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to update password.' });
        if (this.changes === 0) return res.status(404).json({ error: 'User not found during password update.' });
        res.json({ message: 'Password has been reset successfully.' });
    });
});


module.exports = router;