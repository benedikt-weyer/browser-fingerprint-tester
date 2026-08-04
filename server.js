const path = require('node:path');
const express = require('express');

const app = express();
const port = process.env.PORT || 8080;

// Behind a reverse proxy (e.g. in Docker/behind nginx), trust the
// X-Forwarded-For header so req.ip reflects the real client, not the proxy.
app.set('trust proxy', true);

app.get('/api/ip', (req, res) => {
  res.json({
    ip: req.ip,
    forwardedFor: req.headers['x-forwarded-for'] || null,
  });
});

app.use(express.static(path.join(__dirname, 'src')));

app.listen(port, () => {
  console.log(`Browser fingerprint tester listening on port ${port}`);
});
