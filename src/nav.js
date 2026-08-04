const BFT = (() => {
  let sessionPromise = null;

  function getSession() {
    if (!sessionPromise) {
      sessionPromise = fetch('/api/session')
        .then((res) => res.json())
        .catch(() => ({ loggedIn: false }));
    }
    return sessionPromise;
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  async function initNav() {
    const nav = document.getElementById('site-nav');
    const session = await getSession();
    if (!nav) return session;

    const links = ['<a href="index.html">Home</a>'];

    if (session.loggedIn) {
      links.push('<a href="snapshots.html">Snapshots</a>');
      links.push(`<span class="nav-user">Signed in as ${escapeHtml(session.username)}</span>`);
      links.push('<button id="nav-logout" class="nav-button" type="button">Log out</button>');
    } else {
      links.push('<a href="login.html">Log in</a>');
      links.push('<a href="register.html">Register</a>');
    }

    nav.innerHTML = links.join('');

    const logoutButton = document.getElementById('nav-logout');
    if (logoutButton) {
      logoutButton.addEventListener('click', async () => {
        await fetch('/api/logout', { method: 'POST' });
        window.location.href = 'index.html';
      });
    }

    return session;
  }

  return { getSession, initNav, escapeHtml };
})();
