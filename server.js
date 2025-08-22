const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const pg = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.json());
app.use(cors());
app.use(express.static('public')); // Для frontend файлов

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = 'your_secret_key'; // Измените на случайный текст позже

// Создание таблиц в БД (запустится один раз)
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
  );
  CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    from_user_id INT NOT NULL,
    to_user_id INT NOT NULL,
    content TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`).catch(err => console.error('Error creating tables', err));

// Регистрация
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);
    res.status(201).send('User registered');
  } catch (err) {
    res.status(400).send('Username taken');
  }
});

// Вход
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(400).send('User not found');
    const user = result.rows[0];
    if (await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
      res.json({ token });
    } else {
      res.status(400).send('Wrong password');
    }
  } catch (err) {
    res.status(500).send('Error');
  }
});

// Поиск пользователей
app.get('/search-users', authenticateToken, async (req, res) => {
  const { query } = req.query;
  const result = await pool.query('SELECT id, username FROM users WHERE username ILIKE $1', [`%${query}%`]);
  res.json(result.rows);
});

// Получить историю сообщений
app.get('/messages/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const fromUserId = req.user.id;
  const result = await pool.query(
    'SELECT * FROM messages WHERE (from_user_id = $1 AND to_user_id = $2) OR (from_user_id = $2 AND to_user_id = $1) ORDER BY timestamp',
    [fromUserId, userId]
  );
  res.json(result.rows);
});

// Middleware для проверки токена
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).send('No token');
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send('Invalid token');
    req.user = user;
    next();
  });
}

// Socket.io для реального времени
io.on('connection', (socket) => {
  socket.on('join', (userId) => {
    socket.join(userId);
  });

  socket.on('private message', async ({ from, to, content }) => {
    await pool.query('INSERT INTO messages (from_user_id, to_user_id, content) VALUES ($1, $2, $3)', [from, to, content]);
    io.to(to).emit('private message', { from, content });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
