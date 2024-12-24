const socket = io();
let partnerCode = null; // Store partner's code here

document.getElementById('messageInput').addEventListener('keypress', function(e) {
  if (e.key === 'Enter') {
      sendMessage();
  }
});

document.getElementById('codeInput').addEventListener('keypress', function(e) {
  if (e.key === 'Enter') {
      connect();
  }
});

// Set user's assigned code in UI
socket.on('assignedCode', (code) => {
  document.getElementById('chatCode').textContent = code;
});

// Show chat interface if connected
socket.on('connected', (otherPersonsCode) => {
  partnerCode = otherPersonsCode; // Save the partner's code
  document.getElementById('connectForm').classList.remove('active');
  document.getElementById('chatInterface').classList.add('active');
  document.getElementById('errorMsg').textContent = '';
});

// Show error if invalid code
socket.on('errorMsg', (msg) => {
  document.getElementById('errorMsg').textContent = msg;
});

// Receive message
socket.on('messageFrom', (payload) => {
  const container = document.getElementById('chatMessages');
  const messageDiv = document.createElement('div');
  messageDiv.classList.add('message', 'received');
  messageDiv.textContent = payload;
  container.appendChild(messageDiv);
  container.scrollTop = container.scrollHeight;
});

function connect() {
  const codeEntered = document.getElementById('codeInput').value.trim();
  socket.emit('joinWithCode', codeEntered);
}

function sendMessage() {
  const msg = document.getElementById('messageInput').value.trim();
  if (!msg || !partnerCode) return;
  // Send to partner
  socket.emit('messageTo', { code: partnerCode, payload: msg });
  // Display locally
  const container = document.getElementById('chatMessages');
  const messageDiv = document.createElement('div');
  messageDiv.classList.add('message', 'sent');
  messageDiv.textContent = msg;
  container.appendChild(messageDiv);
  document.getElementById('messageInput').value = '';
  container.scrollTop = container.scrollHeight;
}