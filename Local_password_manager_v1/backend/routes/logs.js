const express = require('express');
const router = express.Router();
const db = require('../database');

// GET /api/logs - Fetch audit logs for the authenticated user
router.get('/', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }

    // Default limit to 100 recent logs
    const limit = parseInt(req.query.limit) || 100;

    db.all(
        'SELECT * FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?',
        [userId, limit],
        (err, rows) => {
            if (err) {
                console.error('Database error on fetch logs:', err.message);
                res.status(500).json({ error: err.message });
                return;
            }
            res.json(rows);
        }
    );
});

module.exports = router;
