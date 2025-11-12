const express = require('express');
const cors = require('cors');
// The database import will initialize the db connection and create tables if they don't exist.
const db = require('./database'); 

const vaultRoutes = require('./routes/vault');
const notesRoutes = require('./routes/notes');
const cardsRoutes = require('./routes/cards');
const usersRoutes = require('./routes/users');
const backupRoutes = require('./routes/backup');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// API Routes
app.use('/api/users', usersRoutes);
app.use('/api/vault', vaultRoutes);
app.use('/api/notes', notesRoutes);
app.use('/api/cards', cardsRoutes);
app.use('/api/backup', backupRoutes);

// Health check endpoint
app.get('/', (req, res) => {
  res.send('Password Manager Backend is running!');
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});