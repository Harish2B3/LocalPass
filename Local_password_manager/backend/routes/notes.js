const express = require('express');
const router = express.Router();
const db = require('../database');
const { encrypt, decrypt } = require('../encryption');

// GET all notes for a user
router.get('/', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    db.all('SELECT * FROM notes WHERE user_id = ? ORDER BY title COLLATE NOCASE', [userId], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        const decryptedRows = rows.map(row => ({
            id: row.id,
            title: row.title,
            content: decrypt({ iv: row.content_iv, content: row.content_content })
        }));
        res.json(decryptedRows);
    });
});

// POST a new note for a user
router.post('/', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    const { title, content } = req.body;
    if (!title || content === undefined) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    const encryptedContent = encrypt(content);
    const sql = 'INSERT INTO notes (user_id, title, content_iv, content_content) VALUES (?, ?, ?, ?)';
    db.run(sql, [userId, title, encryptedContent.iv, encryptedContent.content], function(err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.status(201).json({ id: this.lastID, title, content });
    });
});

// PUT (update) an existing note for a user
router.put('/:id', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    const { id } = req.params;
    const { title, content } = req.body;
    if (!title || content === undefined) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const encryptedContent = encrypt(content);
    const sql = `UPDATE notes SET title = ?, content_iv = ?, content_content = ? WHERE id = ? AND user_id = ?`;

    db.run(sql, [title, encryptedContent.iv, encryptedContent.content, id, userId], function(err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Note not found or user not authorized' });
        }
        res.status(200).json({ message: 'Updated successfully' });
    });
});


// DELETE a note for a user
router.delete('/:id', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    db.run('DELETE FROM notes WHERE id = ? AND user_id = ?', [req.params.id, userId], function(err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Note not found or user not authorized' });
        }
        res.status(200).json({ message: 'Deleted successfully' });
    });
});

module.exports = router;