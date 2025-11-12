const sqlite3 = require('sqlite3').verbose();

// This will create a db.sqlite file in the backend directory
const db = new sqlite3.Database('./db.sqlite', (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        createTables();
    }
});

const createTables = () => {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            question1 TEXT,
            answer1_iv TEXT,
            answer1_content TEXT,
            question2 TEXT,
            answer2_iv TEXT,
            answer2_content TEXT
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password_iv TEXT NOT NULL,
            password_content TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content_iv TEXT NOT NULL,
            content_content TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            cardholderName TEXT NOT NULL,
            cardNumber_iv TEXT NOT NULL,
            cardNumber_content TEXT NOT NULL,
            expiryMonth TEXT NOT NULL,
            expiryYear TEXT NOT NULL,
            cvv_iv TEXT NOT NULL,
            cvv_content TEXT NOT NULL,
            gradient TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )`);
        console.log('Tables created or already exist.');
    });
};

module.exports = db;