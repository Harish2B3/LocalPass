
const express = require('express');
const router = express.Router();
const db = require('../database');
const { encrypt } = require('../encryption');

router.post('/import', (req, res) => {
    const userId = req.headers['x-user-id'];
    if (!userId) {
        return res.status(401).json({ error: 'User ID is required' });
    }

    const { meta, data } = req.body;

    // --- Validation ---
    if (!meta || !data || !meta.userId) {
        return res.status(400).json({ error: 'Invalid backup file format.' });
    }
    if (meta.userId !== parseInt(userId, 10)) {
        return res.status(403).json({ error: 'Backup file does not belong to the current user.' });
    }

    // --- Database Transaction ---
    db.serialize(() => {
        db.run('BEGIN TRANSACTION', (err) => {
            if (err) return res.status(500).json({ error: 'Failed to start transaction.' });
        });

        const operations = [];

        // --- Vault Import ---
        if (data.vault && Array.isArray(data.vault)) {
            operations.push(new Promise((resolve, reject) => {
                db.run('DELETE FROM vault WHERE user_id = ?', [userId], (err) => {
                    if (err) return reject(err);
                    if (data.vault.length === 0) return resolve();

                    const stmt = db.prepare('INSERT INTO vault (user_id, service_iv, service_content, username_iv, username_content, password_iv, password_content) VALUES (?, ?, ?, ?, ?, ?, ?)');
                    data.vault.forEach(item => {
                        const encryptedService = encrypt(item.service || '');
                        const encryptedUsername = encrypt(item.username || '');
                        const encryptedPassword = encrypt(item.password || '');

                        stmt.run(
                            userId,
                            encryptedService.iv, encryptedService.content,
                            encryptedUsername.iv, encryptedUsername.content,
                            encryptedPassword.iv, encryptedPassword.content
                        );
                    });
                    stmt.finalize(err => err ? reject(err) : resolve());
                });
            }));
        }

        // --- Notes Import ---
        if (data.notes && Array.isArray(data.notes)) {
            operations.push(new Promise((resolve, reject) => {
                db.run('DELETE FROM notes WHERE user_id = ?', [userId], (err) => {
                    if (err) return reject(err);
                    if (data.notes.length === 0) return resolve();

                    const stmt = db.prepare('INSERT INTO notes (user_id, title_iv, title_content, content_iv, content_content) VALUES (?, ?, ?, ?, ?)');
                    data.notes.forEach(note => {
                        const encryptedTitle = encrypt(note.title || '');
                        const encryptedContent = encrypt(note.content || '');
                        stmt.run(
                            userId,
                            encryptedTitle.iv, encryptedTitle.content,
                            encryptedContent.iv, encryptedContent.content
                        );
                    });
                    stmt.finalize(err => err ? reject(err) : resolve());
                });
            }));
        }

        // --- Cards Import ---
        if (data.cards && Array.isArray(data.cards)) {
            operations.push(new Promise((resolve, reject) => {
                db.run('DELETE FROM cards WHERE user_id = ?', [userId], (err) => {
                    if (err) return reject(err);
                    if (data.cards.length === 0) return resolve();

                    const stmt = db.prepare(`INSERT INTO cards (user_id, cardholderName_iv, cardholderName_content, cardNumber_iv, cardNumber_content, expiryMonth_iv, expiryMonth_content, expiryYear_iv, expiryYear_content, cvv_iv, cvv_content, gradient) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
                    data.cards.forEach(card => {
                        const encryptedCardholderName = encrypt(card.cardholderName || '');
                        const encryptedCardNumber = encrypt(card.cardNumber || '');
                        const encryptedExpiryMonth = encrypt(card.expiryMonth || '');
                        const encryptedExpiryYear = encrypt(card.expiryYear || '');
                        const encryptedCvv = encrypt(card.cvv || '');

                        stmt.run(
                            userId,
                            encryptedCardholderName.iv, encryptedCardholderName.content,
                            encryptedCardNumber.iv, encryptedCardNumber.content,
                            encryptedExpiryMonth.iv, encryptedExpiryMonth.content,
                            encryptedExpiryYear.iv, encryptedExpiryYear.content,
                            encryptedCvv.iv, encryptedCvv.content,
                            card.gradient
                        );
                    });
                    stmt.finalize(err => err ? reject(err) : resolve());
                });
            }));
        }

        Promise.all(operations)
            .then(() => {
                db.run('COMMIT', (err) => {
                    if (err) {
                        console.error("Commit failed:", err);
                        res.status(500).json({ error: 'Failed to commit transaction.' });
                    } else {
                        res.status(200).json({ message: 'Data imported successfully.' });
                    }
                });
            })
            .catch(err => {
                console.error("Import operation failed:", err);
                db.run('ROLLBACK', () => {
                    res.status(500).json({ error: 'An error occurred during import. Operation rolled back.' });
                });
            });
    });
});

module.exports = router;
