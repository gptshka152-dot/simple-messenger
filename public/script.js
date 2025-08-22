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
