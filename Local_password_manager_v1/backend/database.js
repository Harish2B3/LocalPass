const sqlite3 = require('sqlite3').verbose();

// This will create a db.sqlite file in the backend directory
const db = new sqlite3.Database('./db_secure.sqlite', (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        db.run("PRAGMA foreign_keys = ON"); // Enable foreign keys
        createTables();
        runMigrations();
        initSystemConfig();
    }
});

const initSystemConfig = () => {
    db.serialize(() => {
        db.get("SELECT value FROM system_config WHERE key = ?", ["server_id"], (err, row) => {
            if (err) {
                console.error("Error fetching server_id:", err);
                return;
            }
            if (!row) {
                const crypto = require('crypto');
                const serverId = crypto.randomBytes(16).toString('hex');
                db.run("INSERT INTO system_config (key, value) VALUES (?, ?)", ["server_id", serverId], (err) => {
                    if (err) console.error("Error creating server_id:", err);
                    else console.log(`Server Identity Created: ${serverId}`);
                });
            } else {
                console.log(`Server Identity: ${row.value}`);
            }
        });
    });
};

const runMigrations = () => {
    db.serialize(() => {
        // Migration for extension support
        db.all("PRAGMA table_info(users)", (err, rows) => {
            if (err) {
                console.error("Error checking table info:", err);
                return;
            }
            const columns = rows.map(r => r.name);
            if (!columns.includes("extension_username")) {
                console.log("Migrating users table: adding extension columns...");
                db.run("ALTER TABLE users ADD COLUMN extension_username TEXT");
                db.run("ALTER TABLE users ADD COLUMN extension_password_hash TEXT");
                db.run("ALTER TABLE users ADD COLUMN extension_salt TEXT");
                db.run("ALTER TABLE users ADD COLUMN extension_enabled INTEGER DEFAULT 0");
            }
            if (!columns.includes("email")) {
                console.log("Migrating users table: adding email and OTP columns...");
                db.run("ALTER TABLE users ADD COLUMN email TEXT");
                db.run("ALTER TABLE users ADD COLUMN otp_code TEXT");
                db.run("ALTER TABLE users ADD COLUMN otp_expiry DATETIME");
            }
        });
    });
};

const createTables = () => {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            question1_iv TEXT,
            question1_content TEXT,
            answer1_iv TEXT,
            answer1_content TEXT,
            question2_iv TEXT,
            question2_content TEXT,
            answer2_iv TEXT,
            answer2_content TEXT,
            email TEXT,
            otp_code TEXT,
            otp_expiry DATETIME
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            service_iv TEXT NOT NULL,
            service_content TEXT NOT NULL,
            username_iv TEXT NOT NULL,
            username_content TEXT NOT NULL,
            password_iv TEXT NOT NULL,
            password_content TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title_iv TEXT NOT NULL,
            title_content TEXT NOT NULL,
            content_iv TEXT NOT NULL,
            content_content TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            cardholderName_iv TEXT NOT NULL,
            cardholderName_content TEXT NOT NULL,
            cardNumber_iv TEXT NOT NULL,
            cardNumber_content TEXT NOT NULL,
            expiryMonth_iv TEXT NOT NULL,
            expiryMonth_content TEXT NOT NULL,
            expiryYear_iv TEXT NOT NULL,
            expiryYear_content TEXT NOT NULL,
            cvv_iv TEXT NOT NULL,
            cvv_content TEXT NOT NULL,
            gradient TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )`);
        db.run(`CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT
        )`);
        console.log('Tables created or already exist.');
    });
};

module.exports = db;