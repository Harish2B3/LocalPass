
const express = require('express');
const router = express.Router();
const db = require('../database');
const { encrypt, decrypt } = require('../encryption');

// GET all vault items for a user
router.get('/', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    console.log(`GET /api/vault: Fetching all vault entries for user ${userId}.`);
    db.all('SELECT * FROM vault WHERE user_id = ? ORDER BY service COLLATE NOCASE', [userId], (err, rows) => {
        if (err) {
            console.error('Database error on fetch all:', err.message);
            res.status(500).json({ error: err.message });
            return;
        }
        console.log(`Found ${rows.length} entries. Decrypting passwords.`);
        const decryptedRows = rows.map(row => {
            return {
                id: row.id,
                service: row.service,
                username: row.username,
                password: decrypt({ iv: row.password_iv, content: row.password_content })
            };
        });
        console.log('Successfully decrypted all entries.');
        res.json(decryptedRows);
    });
});

// POST a new vault item for a user
router.post('/', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    console.log(`POST /api/vault: Received request to add new entry for user ${userId}.`);
    const { service, username, password } = req.body;

    if (!service || !username) {
        console.error('Validation failed: service or username is missing.');
        return res.status(400).json({ error: 'Service and username are required fields' });
    }
    const encryptedPassword = encrypt(password || '');
    const sql = 'INSERT INTO vault (user_id, service, username, password_iv, password_content) VALUES (?, ?, ?, ?, ?)';
    db.run(sql, [userId, service, username, encryptedPassword.iv, encryptedPassword.content], function(err) {
        if (err) {
            console.error('Database error on insert:', err.message);
            res.status(500).json({ error: err.message });
            return;
        }
        const newEntry = { id: this.lastID, service, username, password: password || '' };
        console.log(`Successfully inserted vault entry with ID: ${this.lastID}`);
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
    console.log(`PUT /api/vault/${id}: Received request to update entry for user ${userId}.`);
    const { service, username, password } = req.body;

    if (!service || !username) {
        console.error('Validation failed: service or username is missing.');
        return res.status(400).json({ error: 'Service and username are required fields' });
    }
    
    const encryptedPassword = encrypt(password || '');
    const sql = `UPDATE vault SET service = ?, username = ?, password_iv = ?, password_content = ? WHERE id = ? AND user_id = ?`;
    
    db.run(sql, [service, username, encryptedPassword.iv, encryptedPassword.content, id, userId], function(err) {
        if (err) {
            console.error('Database error on update:', err.message);
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            console.warn(`Update failed: Vault entry with ID ${id} not found or user not authorized.`);
            return res.status(404).json({ error: 'Item not found or user not authorized' });
        }
        console.log(`Successfully updated vault entry with ID: ${id}`);
        res.status(200).json({ message: 'Updated successfully' });
    });
});


// DELETE a vault item for a user
router.delete('/:id', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    const { id } = req.params;
    console.log(`DELETE /api/vault/${id}: Received request to delete entry for user ${userId}.`);
    db.run('DELETE FROM vault WHERE id = ? AND user_id = ?', [id, userId], function(err) {
        if (err) {
            console.error('Database error on delete:', err.message);
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            console.warn(`Delete failed: Vault entry with ID ${id} not found or user not authorized.`);
            return res.status(404).json({ error: 'Item not found or user not authorized' });
        }
        console.log(`Successfully deleted vault entry with ID: ${id}`);
        res.status(200).json({ message: 'Deleted successfully' });
    });
});

module.exports = router;