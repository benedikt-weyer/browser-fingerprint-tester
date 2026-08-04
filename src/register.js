BFT.initNav();

const form = document.getElementById('register-form');
const message = document.getElementById('form-message');

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  message.textContent = '';

  const username = form.username.value.trim();
  const password = form.password.value;
  const confirmPassword = form['confirm-password'].value;

  if (password !== confirmPassword) {
    message.textContent = 'Passwords do not match.';
    return;
  }

  try {
    const response = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await response.json();
    if (!response.ok) {
      message.textContent = data.error || 'Registration failed.';
      return;
    }
    window.location.href = 'index.html';
  } catch {
    message.textContent = 'Could not reach the server.';
  }
});
