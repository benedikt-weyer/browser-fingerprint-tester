async function init() {
  const session = await BFT.initNav();
  const list = document.getElementById('snapshots-list');
  const message = document.getElementById('snapshots-message');

  if (!session.loggedIn) {
    message.innerHTML = 'You need to <a href="login.html">log in</a> to view your saved snapshots.';
    return;
  }

  try {
    const response = await fetch('/api/snapshots');
    const snapshots = await response.json();
    if (!snapshots.length) {
      message.textContent = 'No snapshots saved yet. Go to the home page and save your current values.';
      return;
    }
    snapshots.forEach((snapshot) => list.appendChild(renderSnapshotItem(snapshot)));
  } catch {
    message.textContent = 'Could not load snapshots.';
  }
}

function renderSnapshotItem(snapshot) {
  const item = document.createElement('li');
  item.className = 'snapshot-item';

  const header = document.createElement('button');
  header.type = 'button';
  header.className = 'snapshot-header';
  header.innerHTML = `<span class="snapshot-name">${BFT.escapeHtml(snapshot.name)}</span><span class="snapshot-time">${BFT.escapeHtml(snapshot.created_at)}</span>`;

  const detail = document.createElement('div');
  detail.className = 'snapshot-detail';
  detail.hidden = true;

  header.addEventListener('click', async () => {
    const wasHidden = detail.hidden;
    detail.hidden = !wasHidden;
    if (wasHidden && !detail.dataset.loaded) {
      detail.textContent = 'Loading…';
      try {
        const response = await fetch(`/api/snapshots/${snapshot.id}`);
        const data = await response.json();
        detail.innerHTML = '';
        const table = document.createElement('table');
        table.className = 'snapshot-table';
        data.values.forEach(({ label, value }) => {
          const row = document.createElement('tr');
          row.innerHTML = `<th>${BFT.escapeHtml(label)}</th><td>${BFT.escapeHtml(value)}</td>`;
          table.appendChild(row);
        });
        detail.appendChild(table);
        detail.dataset.loaded = 'true';
      } catch {
        detail.textContent = 'Could not load snapshot details.';
      }
    }
  });

  item.append(header, detail);
  return item;
}

init();
