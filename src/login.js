BFT.initNav();

const form = document.getElementById('login-form');
const message = document.getElementById('form-message');

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  message.textContent = '';

  const username = form.username.value.trim();
  const password = form.password.value;

  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await response.json();
    if (!response.ok) {
      message.textContent = data.error || 'Login failed.';
      return;
    }
    window.location.href = 'index.html';
  } catch {
    message.textContent = 'Could not reach the server.';
  }
});
