const express = require('express');
const router = express.Router();
const db = require('../database');
const { encrypt, decrypt } = require('../encryption');
const { logAction } = require('../middleware/audit');

// GET all notes for a user
router.get('/', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    db.all('SELECT * FROM notes WHERE user_id = ?', [userId], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        const decryptedRows = rows.map(row => ({
            id: row.id,
            title: decrypt({ iv: row.title_iv, content: row.title_content }),
            content: decrypt({ iv: row.content_iv, content: row.content_content })
        }));

        // Sort by title in memory
        decryptedRows.sort((a, b) => a.title.toLowerCase().localeCompare(b.title.toLowerCase()));

        decryptedRows.sort((a, b) => a.title.toLowerCase().localeCompare(b.title.toLowerCase()));

        logAction(req, 'VIEW_NOTES', 'User viewed secure notes');
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
    const encryptedTitle = encrypt(title);
    const encryptedContent = encrypt(content);

    const sql = 'INSERT INTO notes (user_id, title_iv, title_content, content_iv, content_content) VALUES (?, ?, ?, ?, ?)';
    db.run(sql, [userId, encryptedTitle.iv, encryptedTitle.content, encryptedContent.iv, encryptedContent.content], function (err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.status(201).json({ id: this.lastID, title, content });
        logAction(req, 'CREATE_NOTE', `Created secure note: ${title}`);
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

    const encryptedTitle = encrypt(title);
    const encryptedContent = encrypt(content);

    const sql = `UPDATE notes SET title_iv = ?, title_content = ?, content_iv = ?, content_content = ? WHERE id = ? AND user_id = ?`;

    db.run(sql, [encryptedTitle.iv, encryptedTitle.content, encryptedContent.iv, encryptedContent.content, id, userId], function (err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Note not found or user not authorized' });
        }
        res.status(200).json({ message: 'Updated successfully' });
        logAction(req, 'UPDATE_NOTE', `Updated secure note ID ${id}`);
    });
});


// DELETE a note for a user
router.delete('/:id', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    db.run('DELETE FROM notes WHERE id = ? AND user_id = ?', [req.params.id, userId], function (err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Note not found or user not authorized' });
        }
        res.status(200).json({ message: 'Deleted successfully' });
        logAction(req, 'DELETE_NOTE', `Deleted secure note ID ${req.params.id}`);
    });
});

module.exports = router;