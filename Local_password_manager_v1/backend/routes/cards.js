const express = require('express');
const router = express.Router();
const db = require('../database');
const { encrypt, decrypt } = require('../encryption');
const { logAction } = require('../middleware/audit');

// GET all cards for a user
router.get('/', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    db.all('SELECT * FROM cards WHERE user_id = ?', [userId], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        const decryptedRows = rows.map(row => ({
            id: row.id,
            cardholderName: decrypt({ iv: row.cardholderName_iv, content: row.cardholderName_content }),
            cardNumber: decrypt({ iv: row.cardNumber_iv, content: row.cardNumber_content }),
            expiryMonth: decrypt({ iv: row.expiryMonth_iv, content: row.expiryMonth_content }),
            expiryYear: decrypt({ iv: row.expiryYear_iv, content: row.expiryYear_content }),
            cvv: decrypt({ iv: row.cvv_iv, content: row.cvv_content }),
            gradient: row.gradient,
        }));

        // Sort in memory
        decryptedRows.sort((a, b) => a.cardholderName.toLowerCase().localeCompare(b.cardholderName.toLowerCase()));

        logAction(req, 'VIEW_CARDS', 'User viewed credit cards');
        res.json(decryptedRows);
    });
});

// POST a new card for a user
router.post('/', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    const { cardholderName, cardNumber, expiryMonth, expiryYear, cvv, gradient } = req.body;
    if (!cardholderName || !cardNumber || !expiryMonth || !expiryYear || !cvv || !gradient) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const encryptedCardholderName = encrypt(cardholderName);
    const encryptedCardNumber = encrypt(cardNumber);
    const encryptedExpiryMonth = encrypt(expiryMonth);
    const encryptedExpiryYear = encrypt(expiryYear);
    const encryptedCvv = encrypt(cvv);

    const sql = `INSERT INTO cards (user_id, cardholderName_iv, cardholderName_content, cardNumber_iv, cardNumber_content, expiryMonth_iv, expiryMonth_content, expiryYear_iv, expiryYear_content, cvv_iv, cvv_content, gradient) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    const params = [
        userId,
        encryptedCardholderName.iv, encryptedCardholderName.content,
        encryptedCardNumber.iv, encryptedCardNumber.content,
        encryptedExpiryMonth.iv, encryptedExpiryMonth.content,
        encryptedExpiryYear.iv, encryptedExpiryYear.content,
        encryptedCvv.iv, encryptedCvv.content,
        gradient
    ];
    db.run(sql, params, function (err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }

        res.status(201).json({ id: this.lastID, ...req.body });
        logAction(req, 'CREATE_CARD', `Created credit card ending in ${cardNumber.slice(-4)}`);
    });
});

// PUT (update) an existing card for a user
router.put('/:id', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    const { id } = req.params;
    const { cardholderName, cardNumber, expiryMonth, expiryYear, cvv, gradient } = req.body;
    // Note: gradient was missing in original PUT but usually should be updateable. I'll stick to original logic unless requested? 
    // Wait, original PUT allowed updating everything? 
    // Original PUT body destructure: { cardholderName, cardNumber, expiryMonth, expiryYear, cvv } = req.body;
    // It missed gradient! But the sql updated cardholderName... wait, original PUT didn't update gradient. I won't update gradient then to stay faithful, or I should fix it? I'll stick to the original set of fields but encrypt them.

    if (!cardholderName || !cardNumber || !expiryMonth || !expiryYear || !cvv) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const encryptedCardholderName = encrypt(cardholderName);
    const encryptedCardNumber = encrypt(cardNumber);
    const encryptedExpiryMonth = encrypt(expiryMonth);
    const encryptedExpiryYear = encrypt(expiryYear);
    const encryptedCvv = encrypt(cvv);

    const sql = `UPDATE cards 
                 SET cardholderName_iv = ?, cardholderName_content = ?, 
                     cardNumber_iv = ?, cardNumber_content = ?, 
                     expiryMonth_iv = ?, expiryMonth_content = ?, 
                     expiryYear_iv = ?, expiryYear_content = ?, 
                     cvv_iv = ?, cvv_content = ?
                 WHERE id = ? AND user_id = ?`;
    const params = [
        encryptedCardholderName.iv, encryptedCardholderName.content,
        encryptedCardNumber.iv, encryptedCardNumber.content,
        encryptedExpiryMonth.iv, encryptedExpiryMonth.content,
        encryptedExpiryYear.iv, encryptedExpiryYear.content,
        encryptedCvv.iv, encryptedCvv.content,
        id,
        userId
    ];

    db.run(sql, params, function (err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Card not found or user not authorized' });
        }
        res.status(200).json({ message: 'Updated successfully' });
        logAction(req, 'UPDATE_CARD', `Updated credit card ID ${id}`);
    });
});

// DELETE a card for a user
router.delete('/:id', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    db.run('DELETE FROM cards WHERE id = ? AND user_id = ?', [req.params.id, userId], function (err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Card not found or user not authorized' });
        }
        res.status(200).json({ message: 'Deleted successfully' });
        logAction(req, 'DELETE_CARD', `Deleted credit card ID ${req.params.id}`);
    });
});

module.exports = router;