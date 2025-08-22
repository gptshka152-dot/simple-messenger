const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const pg = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// Настройка Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Настройка Multer для загрузки файлов
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Подключение к PostgreSQL
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = 'your_random_secret_key_123'; // Измените на случайный текст

// Создание таблиц
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    avatar_url TEXT
  );
  CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    from_user_id INT NOT NULL,
    to_user_id INT NOT NULL,
    content TEXT,
    file_url TEXT,
    file_name TEXT,
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
      res.json({ token, avatar_url: user.avatar_url });
    } else {
      res.status(400).send('Wrong password');
    }
  } catch (err) {
    res.status(500).send('Error');
  }
});

// Загрузка аватарки
app.post('/upload-avatar', upload.single('avatar'), authenticateToken, async (req, res) => {
  try {
    const result = await cloudinary.uploader.upload_stream({ resource_type: 'image' }, async (error, result) => {
      if (error) return res.status(500).send('Upload failed');
      await pool.query('UPDATE users SET avatar_url = $1 WHERE id = $2', [result.secure_url, req.user.id]);
      res.json({ avatar_url: result.secure_url });
    }).end(req.file.buffer);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Загрузка файла в чат
app.post('/upload-file', upload.single('file'), authenticateToken, async (req, res) => {
  try {
    const result = await cloudinary.uploader.upload_stream({ resource_type: 'auto' }, (error, result) => {
      if (error) return res.status(500).send('Upload failed');
      res.json({ file_url: result.secure_url, file_name: req.file.originalname });
    }).end(req.file.buffer);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Поиск пользователей
app.get('/search-users', authenticateToken, async (req, res) => {
  const { query } = req.query;
  const result = await pool.query('SELECT id, username, avatar_url FROM users WHERE username ILIKE $1 AND id != $2', [`%${query}%`, req.user.id]);
  res.json(result.rows);
});

// Получить историю сообщений
app.get('/messages/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const fromUserId = req.user.id;
  const result = await pool.query(
    'SELECT m.*, u1.username as from_username, u2.username as to_username, u1.avatar_url as from_avatar, u2.avatar_url as to_avatar ' +
    'FROM messages m ' +
    'JOIN users u1 ON m.from_user_id = u1.id ' +
    'JOIN users u2 ON m.to_user_id = u2.id ' +
    'WHERE (from_user_id = $1 AND to_user_id = $2) OR (from_user_id = $2 AND to_user_id = $1) ORDER BY timestamp',
    [fromUserId, userId]
  );
  res.json(result.rows);
});

// Получить список чатов
app.get('/chats', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const result = await pool.query(
    'SELECT DISTINCT ON (u.id) u.id, u.username, u.avatar_url, m.timestamp ' +
    'FROM users u ' +
    'JOIN messages m ON (m.from_user_id = u.id AND m.to_user_id = $1) OR (m.from_user_id = $1 AND m.to_user_id = u.id) ' +
    'ORDER BY u.id, m.timestamp DESC',
    [userId]
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

  socket.on('private message', async ({ from, to, content, file_url, file_name }) => {
    const result = await pool.query(
      'INSERT INTO messages (from_user_id, to_user_id, content, file_url, file_name) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [from, to, content, file_url, file_name]
    );
    const message = result.rows[0];
    io.to(to).emit('private message', {
      from,
      content,
      file_url,
      file_name,
      timestamp: message.timestamp,
      from_username: (await pool.query('SELECT username FROM users WHERE id = $1', [from])).rows[0].username,
      from_avatar: (await pool.query('SELECT avatar_url FROM users WHERE id = $1', [from])).rows[0].avatar_url
    });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));    console.error('Database connection error:', err.stack);
  } else {
    console.log('Connected to database');
  }
});

const JWT_SECRET = 'mysecret123456789'; // Заменено на уникальный ключ

// Создание таблиц
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    avatar_url TEXT
  );
  CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    from_user_id INT NOT NULL,
    to_user_id INT NOT NULL,
    content TEXT,
    type VARCHAR(20) DEFAULT 'text',
    file_name TEXT,
    file_url TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`).catch(err => console.error('Error creating tables:', err.stack));

// Регистрация
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);
    res.status(201).send('User registered');
  } catch (err) {
    console.error('Register error:', err.stack);
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
      res.json({ token, avatar_url: user.avatar_url });
    } else {
      res.status(400).send('Wrong password');
    }
  } catch (err) {
    console.error('Login error:', err.stack);
    res.status(500).send('Server error');
  }
});

// Загрузка аватарки
app.post('/upload-avatar', upload.single('avatar'), authenticateToken, async (req, res) => {
  try {
    if (!req.file) return res.status(400).send('No file uploaded');
    const result = await cloudinary.uploader.upload(req.file.path);
    await pool.query('UPDATE users SET avatar_url = $1 WHERE id = $2', [result.secure_url, req.user.id]);
    res.json({ avatar_url: result.secure_url });
  } catch (err) {
    console.error('Upload avatar error:', err.stack);
    res.status(500).send('Error uploading avatar');
  }
});

// Загрузка файла/фото
app.post('/upload-file', upload.single('file'), authenticateToken, async (req, res) => {
  try {
    if (!req.file) return res.status(400).send('No file uploaded');
    const result = await cloudinary.uploader.upload(req.file.path, { resource_type: 'auto' });
    res.json({ file_url: result.secure_url, file_name: req.file.originalname });
  } catch (err) {
    console.error('Upload file error:', err.stack);
    res.status(500).send('Error uploading file');
  }
});

// Поиск пользователей
app.get('/search-users', authenticateToken, async (req, res) => {
  const { query } = req.query;
  if (!query) return res.status(400).send('Query parameter is required');
  try {
    const result = await pool.query('SELECT id, username, avatar_url FROM users WHERE username ILIKE $1', [`%${query}%`]);
    res.json(result.rows);
  } catch (err) {
    console.error('Search users error:', err.stack);
    res.status(500).send('Error searching users');
  }
});

// Получить список чатов
app.get('/chats', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  try {
    const result = await pool.query(`
      SELECT DISTINCT ON (u.id) u.id, u.username, u.avatar_url
      FROM users u
      JOIN messages m ON u.id = m.from_user_id OR u.id = m.to_user_id
      WHERE (m.from_user_id = $1 OR m.to_user_id = $1) AND u.id != $1
    `, [userId]);
    res.json(result.rows);
  } catch (err) {
    console.error('Get chats error:', err.stack);
    res.status(500).send('Error fetching chats');
  }
});

// Получить историю сообщений
app.get('/messages/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const fromUserId = req.user.id;
  try {
    const result = await pool.query(
      'SELECT m.*, u.username, u.avatar_url FROM messages m JOIN users u ON m.from_user_id = u.id WHERE (m.from_user_id = $1 AND m.to_user_id = $2) OR (m.from_user_id = $2 AND m.to_user_id = $1) ORDER BY m.timestamp',
      [fromUserId, userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Get messages error:', err.stack);
    res.status(500).send('Error fetching messages');
  }
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

// Socket.io
io.on('connection', (socket) => {
  socket.on('join', (userId) => {
    socket.join(userId);
    console.log(`User ${userId} joined`);
  });

  socket.on('private message', async ({ from, to, content, type, file_name, file_url }) => {
    try {
      const result = await pool.query(
        'INSERT INTO messages (from_user_id, to_user_id, content, type, file_name, file_url) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
        [from, to, content, type, file_name, file_url]
      );
      const message = result.rows[0];
      const username = (await pool.query('SELECT username FROM users WHERE id = $1', [from])).rows[0].username;
      io.to(to).emit('private message', { ...message, username });
      io.to(from).emit('private message', { ...message, username });
    } catch (err) {
      console.error('Socket message error:', err.stack);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    avatar_url TEXT
  );
  CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    from_user_id INT NOT NULL,
    to_user_id INT NOT NULL,
    content TEXT,
    type VARCHAR(20) DEFAULT 'text',
    file_name TEXT,
    file_url TEXT,
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
      res.json({ token, avatar_url: user.avatar_url });
    } else {
      res.status(400).send('Wrong password');
    }
  } catch (err) {
    res.status(500).send('Error');
  }
});

// Загрузка аватарки
app.post('/upload-avatar', upload.single('avatar'), authenticateToken, async (req, res) => {
  try {
    const result = await cloudinary.uploader.upload(req.file.path);
    await pool.query('UPDATE users SET avatar_url = $1 WHERE id = $2', [result.secure_url, req.user.id]);
    res.json({ avatar_url: result.secure_url });
  } catch (err) {
    res.status(500).send('Error uploading avatar');
  }
});

// Загрузка файла/фото в чат
app.post('/upload-file', upload.single('file'), authenticateToken, async (req, res) => {
  try {
    const result = await cloudinary.uploader.upload(req.file.path, { resource_type: 'auto' });
    res.json({ file_url: result.secure_url, file_name: req.file.originalname });
  } catch (err) {
    res.status(500).send('Error uploading file');
  }
});

// Поиск пользователей
app.get('/search-users', authenticateToken, async (req, res) => {
  const { query } = req.query;
  const result = await pool.query('SELECT id, username, avatar_url FROM users WHERE username ILIKE $1', [`%${query}%`]);
  res.json(result.rows);
});

// Получить список чатов (уникальные собеседники)
app.get('/chats', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const result = await pool.query(`
    SELECT DISTINCT ON (u.id) u.id, u.username, u.avatar_url
    FROM users u
    JOIN messages m ON u.id = m.from_user_id OR u.id = m.to_user_id
    WHERE (m.from_user_id = $1 OR m.to_user_id = $1) AND u.id != $1
  `, [userId]);
  res.json(result.rows);
});

// Получить историю сообщений
app.get('/messages/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;
  const fromUserId = req.user.id;
  const result = await pool.query(
    'SELECT m.*, u.username, u.avatar_url FROM messages m JOIN users u ON m.from_user_id = u.id WHERE (m.from_user_id = $1 AND m.to_user_id = $2) OR (m.from_user_id = $2 AND m.to_user_id = $1) ORDER BY m.timestamp',
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

// Socket.io
io.on('connection', (socket) => {
  socket.on('join', (userId) => {
    socket.join(userId);
  });

  socket.on('private message', async ({ from, to, content, type, file_name, file_url }) => {
    const result = await pool.query(
      'INSERT INTO messages (from_user_id, to_user_id, content, type, file_name, file_url) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [from, to, content, type, file_name, file_url]
    );
    const message = result.rows[0];
    io.to(to).emit('private message', { ...message, username: (await pool.query('SELECT username FROM users WHERE id = $1', [from])).rows[0].username });
    io.to(from).emit('private message', { ...message, username: (await pool.query('SELECT username FROM users WHERE id = $1', [from])).rows[0].username });
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));`).catch(err => console.error('Error creating tables', err));

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
