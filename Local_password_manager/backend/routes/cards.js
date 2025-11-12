const express = require('express');
const router = express.Router();
const db = require('../database');
const { encrypt, decrypt } = require('../encryption');

// GET all cards for a user
router.get('/', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    db.all('SELECT * FROM cards WHERE user_id = ? ORDER BY cardholderName COLLATE NOCASE', [userId], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        const decryptedRows = rows.map(row => ({
            id: row.id,
            cardholderName: row.cardholderName,
            cardNumber: decrypt({ iv: row.cardNumber_iv, content: row.cardNumber_content }),
            expiryMonth: row.expiryMonth,
            expiryYear: row.expiryYear,
            cvv: decrypt({ iv: row.cvv_iv, content: row.cvv_content }),
            gradient: row.gradient,
        }));
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
    const encryptedCardNumber = encrypt(cardNumber);
    const encryptedCvv = encrypt(cvv);
    const sql = `INSERT INTO cards (user_id, cardholderName, cardNumber_iv, cardNumber_content, expiryMonth, expiryYear, cvv_iv, cvv_content, gradient) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
    const params = [
        userId,
        cardholderName, 
        encryptedCardNumber.iv, encryptedCardNumber.content,
        expiryMonth, 
        expiryYear, 
        encryptedCvv.iv, encryptedCvv.content,
        gradient
    ];
    db.run(sql, params, function(err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.status(201).json({ id: this.lastID, ...req.body });
    });
});

// PUT (update) an existing card for a user
router.put('/:id', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    const { id } = req.params;
    const { cardholderName, cardNumber, expiryMonth, expiryYear, cvv } = req.body;
    if (!cardholderName || !cardNumber || !expiryMonth || !expiryYear || !cvv) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const encryptedCardNumber = encrypt(cardNumber);
    const encryptedCvv = encrypt(cvv);
    
    const sql = `UPDATE cards 
                 SET cardholderName = ?, cardNumber_iv = ?, cardNumber_content = ?, 
                     expiryMonth = ?, expiryYear = ?, cvv_iv = ?, cvv_content = ?
                 WHERE id = ? AND user_id = ?`;
    const params = [
        cardholderName,
        encryptedCardNumber.iv, encryptedCardNumber.content,
        expiryMonth,
        expiryYear,
        encryptedCvv.iv, encryptedCvv.content,
        id,
        userId
    ];
    
    db.run(sql, params, function(err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Card not found or user not authorized' });
        }
        res.status(200).json({ message: 'Updated successfully' });
    });
});

// DELETE a card for a user
router.delete('/:id', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }
    db.run('DELETE FROM cards WHERE id = ? AND user_id = ?', [req.params.id, userId], function(err) {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
         if (this.changes === 0) {
            return res.status(404).json({ error: 'Card not found or user not authorized' });
        }
        res.status(200).json({ message: 'Deleted successfully' });
    });
});

module.exports = router;