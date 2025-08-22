const socket = io();
let token = localStorage.getItem('token');
let currentChatUserId = null;
let userAvatar = localStorage.getItem('avatar_url');

if (token) {
  showMessenger();
  loadChats();
}

async function register() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const response = await fetch('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  if (response.ok) alert('Registered! Now login.');
  else alert(await response.text());
}

async function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const response = await fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  if (response.ok) {
    const data = await response.json();
    token = data.token;
    userAvatar = data.avatar_url;
    localStorage.setItem('token', token);
    localStorage.setItem('avatar_url', userAvatar);
    showMessenger();
    loadChats();
  } else {
    alert(await response.text());
  }
}

function showMessenger() {
  document.getElementById('auth').style.display = 'none';
  document.getElementById('messenger').style.display = 'flex';
  socket.emit('join', getUserIdFromToken());
  const darkTheme = localStorage.getItem('darkTheme') === 'true';
  document.getElementById('dark-theme').checked = darkTheme;
  if (darkTheme) document.body.classList.add('dark');
}

async function loadChats() {
  const response = await fetch('/chats', {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const chats = await response.json();
  const chatList = document.getElementById('chat-list');
  chatList.innerHTML = '';
  chats.forEach(chat => {
    const li = document.createElement('li');
    li.innerHTML = `<img src="${chat.avatar_url || 'https://via.placeholder.com/40'}" alt="">${chat.username}`;
    li.onclick = () => startChat(chat.id, chat.username, chat.avatar_url);
    chatList.appendChild(li);
  });
}

async function searchUsers() {
  const query = document.getElementById('search').value;
  if (!query) return loadChats();
  const response = await fetch(`/search-users?query=${query}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const users = await response.json();
  const chatList = document.getElementById('chat-list');
  chatList.innerHTML = '';
  users.forEach(user => {
    const li = document.createElement('li');
    li.innerHTML = `<img src="${user.avatar_url || 'https://via.placeholder.com/40'}" alt="">${user.username}`;
    li.onclick = () => startChat(user.id, user.username, user.avatar_url);
    chatList.appendChild(li);
  });
}

async function startChat(userId, username, avatarUrl) {
  currentChatUserId = userId;
  document.getElementById('chat-with').textContent = username;
  document.getElementById('chat-avatar').src = avatarUrl || 'https://via.placeholder.com/40';
  document.getElementById('chat-avatar').style.display = 'inline';
  const response = await fetch(`/messages/${userId}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const messages = await response.json();
  const msgDiv = document.getElementById('messages');
  msgDiv.innerHTML = '';
  messages.forEach(msg => {
    displayMessage(msg);
  });
  msgDiv.scrollTop = msgDiv.scrollHeight;
}

function displayMessage(msg) {
  const msgDiv = document.getElementById('messages');
  const div = document.createElement('div');
  div.className = `message ${msg.from_user_id === getUserIdFromToken() ? 'mine' : 'theirs'}`;
  if (msg.type === 'text') {
    div.innerHTML = `<p>${msg.content}</p>`;
  } else if (msg.type === 'image') {
    div.innerHTML = `<img src="${msg.file_url}" alt="Image">`;
  } else if (msg.type === 'file') {
    div.innerHTML = `<div class="file"><i class="fas fa-file"></i>${msg.file_name}</div>`;
  }
  div.innerHTML += `<div class="timestamp">${new Date(msg.timestamp).toLocaleTimeString()}</div>`;
  msgDiv.appendChild(div);
}

async function sendMessage() {
  const content = document.getElementById('message-input').value;
  if (!content || !currentChatUserId) return;
  socket.emit('private message', { from: getUserIdFromToken(), to: currentChatUserId, content, type: 'text' });
  document.getElementById('message-input').value = '';
}

async function uploadFile() {
  const fileInput = document.getElementById('file-input');
  const file = fileInput.files[0];
  if (!file || !currentChatUserId) return;
  const formData = new FormData();
  formData.append('file', file);
  const response = await fetch('/upload-file', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}` },
    body: formData
  });
  const { file_url, file_name } = await response.json();
  const type = file.type.startsWith('image/') ? 'image' : 'file';
  socket.emit('private message', { from: getUserIdFromToken(), to: currentChatUserId, content: '', type, file_name, file_url });
  fileInput.value = '';
}

async function uploadAvatar() {
  const avatarInput = document.getElementById('avatar-input');
  const file = avatarInput.files[0];
  if (!file) return;
  const formData = new FormData();
  formData.append('avatar', file);
  const response = await fetch('/upload-avatar', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}` },
    body: formData
  });
  const { avatar_url } = await response.json();
  userAvatar = avatar_url;
  localStorage.setItem('avatar_url', avatar_url);
  alert('Avatar updated!');
}

function toggleSettings() {
  document.getElementById('settings').classList.toggle('open');
}

function toggleTheme() {
  const darkTheme = document.getElementById('dark-theme').checked;
  document.body.classList.toggle('dark', darkTheme);
  localStorage.setItem('darkTheme', darkTheme);
}

function logout() {
  localStorage.removeItem('token');
  localStorage.removeItem('avatar_url');
  window.location.reload();
}

socket.on('private message', (msg) => {
  if (msg.from_user_id === currentChatUserId || msg.to_user_id === currentChatUserId) {
    displayMessage(msg);
    document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
  }
});

function getUserIdFromToken() {
  const payload = JSON.parse(atob(token.split('.')[1]));
  return payload.id;
}    console.error('Database connection error:', err.stack);
  } else {
    console.log('Connected to database');
  }
});

const JWT_SECRET = 'your_secret_key_change_me';

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
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));    showMessenger();
    loadChats();
  } else {
    alert(await response.text());
  }
}

function showMessenger() {
  document.getElementById('auth').style.display = 'none';
  document.getElementById('messenger').style.display = 'flex';
  socket.emit('join', getUserIdFromToken());
  const darkTheme = localStorage.getItem('darkTheme') === 'true';
  document.getElementById('dark-theme').checked = darkTheme;
  if (darkTheme) document.body.classList.add('dark');
}

async function loadChats() {
  const response = await fetch('/chats', {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const chats = await response.json();
  const chatList = document.getElementById('chat-list');
  chatList.innerHTML = '';
  chats.forEach(chat => {
    const li = document.createElement('li');
    li.innerHTML = `<img src="${chat.avatar_url || 'https://via.placeholder.com/40'}" alt="">${chat.username}`;
    li.onclick = () => startChat(chat.id, chat.username, chat.avatar_url);
    chatList.appendChild(li);
  });
}

async function searchUsers() {
  const query = document.getElementById('search').value;
  if (!query) return loadChats();
  const response = await fetch(`/search-users?query=${query}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const users = await response.json();
  const chatList = document.getElementById('chat-list');
  chatList.innerHTML = '';
  users.forEach(user => {
    const li = document.createElement('li');
    li.innerHTML = `<img src="${user.avatar_url || 'https://via.placeholder.com/40'}" alt="">${user.username}`;
    li.onclick = () => startChat(user.id, user.username, user.avatar_url);
    chatList.appendChild(li);
  });
}

async function startChat(userId, username, avatarUrl) {
  currentChatUserId = userId;
  document.getElementById('chat-with').textContent = username;
  document.getElementById('chat-avatar').src = avatarUrl || 'https://via.placeholder.com/40';
  document.getElementById('chat-avatar').style.display = 'inline';
  const response = await fetch(`/messages/${userId}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const messages = await response.json();
  const msgDiv = document.getElementById('messages');
  msgDiv.innerHTML = '';
  messages.forEach(msg => {
    displayMessage(msg);
  });
  msgDiv.scrollTop = msgDiv.scrollHeight;
}

function displayMessage(msg) {
  const msgDiv = document.getElementById('messages');
  const div = document.createElement('div');
  div.className = `message ${msg.from_user_id === getUserIdFromToken() ? 'mine' : 'theirs'}`;
  if (msg.type === 'text') {
    div.innerHTML = `<p>${msg.content}</p>`;
  } else if (msg.type === 'image') {
    div.innerHTML = `<img src="${msg.file_url}" alt="Image">`;
  } else if (msg.type === 'file') {
    div.innerHTML = `<div class="file"><i class="fas fa-file"></i>${msg.file_name}</div>`;
  }
  div.innerHTML += `<div class="timestamp">${new Date(msg.timestamp).toLocaleTimeString()}</div>`;
  msgDiv.appendChild(div);
}

async function sendMessage() {
  const content = document.getElementById('message-input').value;
  if (!content || !currentChatUserId) return;
  socket.emit('private message', { from: getUserIdFromToken(), to: currentChatUserId, content, type: 'text' });
  document.getElementById('message-input').value = '';
}

async function uploadFile() {
  const fileInput = document.getElementById('file-input');
  const file = fileInput.files[0];
  if (!file || !currentChatUserId) return;
  const formData = new FormData();
  formData.append('file', file);
  const response = await fetch('/upload-file', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}` },
    body: formData
  });
  const { file_url, file_name } = await response.json();
  const type = file.type.startsWith('image/') ? 'image' : 'file';
  socket.emit('private message', { from: getUserIdFromToken(), to: currentChatUserId, content: '', type, file_name, file_url });
  fileInput.value = '';
}

async function uploadAvatar() {
  const avatarInput = document.getElementById('avatar-input');
  const file = avatarInput.files[0];
  if (!file) return;
  const formData = new FormData();
  formData.append('avatar', file);
  const response = await fetch('/upload-avatar', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${token}` },
    body: formData
  });
  const { avatar_url } = await response.json();
  userAvatar = avatar_url;
  localStorage.setItem('avatar_url', avatar_url);
  alert('Avatar updated!');
}

function toggleSettings() {
  document.getElementById('settings').classList.toggle('open');
}

function toggleTheme() {
  const darkTheme = document.getElementById('dark-theme').checked;
  document.body.classList.toggle('dark', darkTheme);
  localStorage.setItem('darkTheme', darkTheme);
}

function logout() {
  localStorage.removeItem('token');
  localStorage.removeItem('avatar_url');
  window.location.reload();
}

socket.on('private message', (msg) => {
  if (msg.from_user_id === currentChatUserId || msg.to_user_id === currentChatUserId) {
    displayMessage(msg);
    document.getElementById('messages').scrollTop = document.getElementById('messages').scrollHeight;
  }
});

function getUserIdFromToken() {
  const payload = JSON.parse(atob(token.split('.')[1]));
  return payload.id;
}}

function showMessenger() {
  document.getElementById('auth').style.display = 'none';
  document.getElementById('messenger').style.display = 'block';
  socket.emit('join', getUserIdFromToken());
}

async function searchUsers() {
  const query = document.getElementById('search').value;
  if (!query) return;
  const response = await fetch(`/search-users?query=${query}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const users = await response.json();
  const list = document.getElementById('user-list');
  list.innerHTML = '';
  users.forEach(user => {
    const li = document.createElement('li');
    li.textContent = user.username;
    li.onclick = () => startChat(user.id, user.username);
    list.appendChild(li);
  });
}

async function startChat(userId, username) {
  currentChatUserId = userId;
  document.getElementById('chat-with').textContent = `Чат с ${username}`;
  const response = await fetch(`/messages/${userId}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const messages = await response.json();
  const msgDiv = document.getElementById('messages');
  msgDiv.innerHTML = '';
  messages.forEach(msg => {
    msgDiv.innerHTML += `<p>${msg.from_user_id === getUserIdFromToken() ? 'You' : 'They'}: ${msg.content}</p>`;
  });
  msgDiv.scrollTop = msgDiv.scrollHeight;
}

function sendMessage() {
  const content = document.getElementById('message-input').value;
  if (!content || !currentChatUserId) return;
  socket.emit('private message', { from: getUserIdFromToken(), to: currentChatUserId, content });
  document.getElementById('message-input').value = '';
  const msgDiv = document.getElementById('messages');
  msgDiv.innerHTML += `<p>You: ${content}</p>`;
  msgDiv.scrollTop = msgDiv.scrollHeight;
}

socket.on('private message', ({ from, content }) => {
  if (from === currentChatUserId) {
    const msgDiv = document.getElementById('messages');
    msgDiv.innerHTML += `<p>They: ${content}</p>`;
    msgDiv.scrollTop = msgDiv.scrollHeight;
  }
});

function getUserIdFromToken() {
  const payload = JSON.parse(atob(token.split('.')[1]));
  return payload.id;
  }
