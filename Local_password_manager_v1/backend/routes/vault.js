
const checkPasswordStrength = (password) => {
    let score = 0;
    if (!password) return 0;
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    return score;
};

const express = require('express');
const router = express.Router();
const db = require('../database');
const { encrypt, decrypt } = require('../encryption');
const { logAction } = require('../middleware/audit');

// GET dashboard stats
router.get('/stats', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }

    db.all('SELECT * FROM vault WHERE user_id = ?', [userId], (err, rows) => {
        if (err) {
            console.error('Database error on fetch stats:', err.message);
            res.status(500).json({ error: err.message });
            return;
        }

        let totalPasswords = 0;
        let weakPasswords = 0;
        let totalScore = 0;
        let strongest = { service: "N/A", score: -1 };
        let weakest = { service: "N/A", score: 6 };

        rows.forEach(row => {
            // Decrypt password only to calculate stats
            const password = decrypt({ iv: row.password_iv, content: row.password_content });
            const service = decrypt({ iv: row.service_iv, content: row.service_content });

            totalPasswords++;

            // Replicate frontend logic: score <= 2 is weak
            let score = 0;
            if (password && password.length > 0) {
                score = checkPasswordStrength(password);
            }

            totalScore += score;

            if (score <= 2) {
                weakPasswords++;
            }

            if (score > strongest.score) {
                strongest = { service: service, score: score };
            }
            // Logic for weakest: if score < current weakest OR (current weakest is N/A and we have a score)
            if (score < weakest.score) {
                weakest = { service: service, score: score };
            }
        });

        // Default strongest/weakest if no passwords
        if (strongest.score === -1) strongest.service = "N/A";
        if (weakest.score === 6) weakest.service = "N/A";


        const averageScore = totalPasswords > 0 ? totalScore / totalPasswords : 0;
        const securityScore = Math.round((averageScore / 5) * 100);

        res.json({
            totalPasswords,
            weakPasswords,
            securityScore,
            strongest: strongest.service,
            weakest: weakest.service
        });
    });
});

// GET all vault items for a user (Masked Passwords)
router.get('/', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }

    db.all('SELECT * FROM vault WHERE user_id = ?', [userId], (err, rows) => {
        if (err) {
            console.error('Database error on fetch all:', err.message);
            res.status(500).json({ error: err.message });
            return;
        }

        const decryptedRows = rows.map(row => {
            return {
                id: row.id,
                service: decrypt({ iv: row.service_iv, content: row.service_content }),
                username: decrypt({ iv: row.username_iv, content: row.username_content }),
                password: '******' // MASKED PASSWORD
            };
        });

        // Sort by service name in memory since DB fields are encrypted
        decryptedRows.sort((a, b) => a.service.toLowerCase().localeCompare(b.service.toLowerCase()));

        logAction(req, 'VIEW_VAULT', 'User viewed vault items');
        res.json(decryptedRows);
    });
});

// POST /reveal-password — Fetch decrypted password for a specific vault item
// Uses POST so the item ID is never exposed in URL, server logs, or proxy history
router.post('/reveal-password', (req, res) => {
    const userId = req.headers['x-user-id'];
    const { id } = req.body;

    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }

    if (!id) {
        return res.status(400).json({ error: 'Item ID is required' });
    }

    db.get('SELECT password_iv, password_content FROM vault WHERE id = ? AND user_id = ?', [id, userId], (err, row) => {
        if (err) {
            console.error('Database error on reveal password:', err.message);
            return res.status(500).json({ error: 'Database error' });
        }
        if (!row) {
            return res.status(404).json({ error: 'Item not found' });
        }

        const password = decrypt({ iv: row.password_iv, content: row.password_content });
        logAction(req, 'REVEAL_PASSWORD', `Revealed password for vault item`); // No ID in log
        res.json({ password });
    });
});

// POST a new vault item for a user
router.post('/', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }

    const { service, username, password } = req.body;

    if (!service) {
        console.error('Validation failed: service is missing.');
        return res.status(400).json({ error: 'Service (URL) is required' });
    }

    const encryptedService = encrypt(service);
    const encryptedUsername = encrypt(username || '');
    const encryptedPassword = encrypt(password || '');

    const sql = 'INSERT INTO vault (user_id, service_iv, service_content, username_iv, username_content, password_iv, password_content) VALUES (?, ?, ?, ?, ?, ?, ?)';
    db.run(sql, [userId, encryptedService.iv, encryptedService.content, encryptedUsername.iv, encryptedUsername.content, encryptedPassword.iv, encryptedPassword.content], function (err) {
        if (err) {
            console.error('Database error on insert:', err.message);
            res.status(500).json({ error: err.message });
            return;
        }
        const newEntry = { id: this.lastID, service, username: username || '', password: password || '' };

        logAction(req, 'CREATE_VAULT_ITEM', `Created vault item for ${service}`);
        res.status(201).json(newEntry);
    });
});

// PUT (update) an existing vault item for a user
router.put('/:id', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    const { id } = req.params;

    const { service, username, password } = req.body;

    if (!service) {
        console.error('Validation failed: service is missing.');
        return res.status(400).json({ error: 'Service (URL) is required' });
    }

    const encryptedService = encrypt(service);
    const encryptedUsername = encrypt(username || '');
    const encryptedPassword = encrypt(password || '');

    const sql = `UPDATE vault SET service_iv = ?, service_content = ?, username_iv = ?, username_content = ?, password_iv = ?, password_content = ? WHERE id = ? AND user_id = ?`;

    db.run(sql, [
        encryptedService.iv, encryptedService.content,
        encryptedUsername.iv, encryptedUsername.content,
        encryptedPassword.iv, encryptedPassword.content,
        id, userId
    ], function (err) {
        if (err) {
            console.error('Database error on update:', err.message);
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            console.warn(`Update failed: Vault entry with ID ${id} not found or user not authorized.`);
            return res.status(404).json({ error: 'Item not found or user not authorized' });
        }

        res.status(200).json({ message: 'Updated successfully' });
        logAction(req, 'UPDATE_VAULT_ITEM', `Updated vault item ID ${id} for ${service}`);
    });
});


// DELETE a vault item for a user
router.delete('/:id', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    const { id } = req.params;

    db.run('DELETE FROM vault WHERE id = ? AND user_id = ?', [id, userId], function (err) {
        if (err) {
            console.error('Database error on delete:', err.message);
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            console.warn(`Delete failed: Vault entry with ID ${id} not found or user not authorized.`);
            return res.status(404).json({ error: 'Item not found or user not authorized' });
        }

        res.status(200).json({ message: 'Deleted successfully' });
        logAction(req, 'DELETE_VAULT_ITEM', `Deleted vault item ID ${id}`);
    });
});

module.exports = router;