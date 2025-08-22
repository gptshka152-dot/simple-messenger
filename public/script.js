const socket = io();
let token = localStorage.getItem('token');
let currentChatUserId = null;

if (token) {
  showMessenger();
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
    localStorage.setItem('token', token);
    showMessenger();
  } else {
    alert(await response.text());
  }
}

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
