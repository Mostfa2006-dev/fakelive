const express    = require('express');
const http       = require('http');
const WebSocket  = require('ws');
const path       = require('path');
const { v4: uuidv4 } = require('uuid');
const bcrypt     = require('bcryptjs');
const mongoose   = require('mongoose');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server, perMessageDeflate: false });

const PORT           = process.env.PORT || 3000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'fakelive2024';
const MONGODB_URI    = process.env.MONGODB_URI;

const WS_PING_INTERVAL = 25000;

// ── MONGODB SCHEMA ──
const userSchema = new mongoose.Schema({
  username:       { type: String, unique: true, required: true },
  password:       { type: String, required: true },
  plain_password: { type: String },
  role:           { type: String, enum: ['streamer', 'viewer'], required: true },
  status:         { type: String, enum: ['pending', 'approved', 'rejected', 'banned'], default: 'pending' },
  ban_reason:     { type: String, default: null },
  created_at:     { type: Number, default: () => Date.now() },
});
const User = mongoose.model('User', userSchema);

async function initDb() {
  if (!MONGODB_URI) { console.error('❌ MONGODB_URI not set!'); process.exit(1); }
  await mongoose.connect(MONGODB_URI);
  console.log('✅ MongoDB connected');
}

// ── IN-MEMORY STORES ──
const rooms        = new Map();
const adminSockets = new Set();
const bannedUsers  = new Map();
const ipBans       = new Map();
const adminLog     = [];
const ipUserMap    = new Map();
const persistedMeta = new Map(); // roomId -> last meta payload

app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// ── UTILS ──
const send = (ws, msg) => {
  if (ws?.readyState === WebSocket.OPEN) {
    try { ws.send(JSON.stringify(msg)); } catch (e) {}
  }
};

function broadcast(room, msg, exclude = null) {
  const d = JSON.stringify(msg);
  if (room.streamer && room.streamer !== exclude && room.streamer.readyState === WebSocket.OPEN) {
    try { room.streamer.send(d); } catch (e) {}
  }
  room.viewers.forEach(v => {
    if (v !== exclude && v.readyState === WebSocket.OPEN) {
      try { v.send(d); } catch (e) {}
    }
  });
}

function logAction(action, target, reason, admin) {
  adminLog.push({ id: uuidv4(), action, target, reason: reason || '', admin, timestamp: Date.now() });
  if (adminLog.length > 500) adminLog.shift();
}

async function notifyAdmins() {
  const state = await buildState();
  const msg = JSON.stringify({ type: 'admin_state', state });
  adminSockets.forEach(a => { if (a.readyState === WebSocket.OPEN) { try { a.send(msg); } catch (e) {} } });
}

async function buildState() {
  const state = { rooms: [], pendingAccounts: [], allUsers: [], bannedUsers: [], ipBans: [], recentLog: [] };
  rooms.forEach((room, roomId) => {
    state.rooms.push({
      roomId,
      streamer: room.streamer ? { username: room.streamer.username, id: room.streamer.id, ip: room.streamer.ip } : null,
      viewers: [...room.viewers].map(v => ({ username: v.username, id: v.id, ip: v.ip })),
      hasPassword: !!room.password,
    });
  });
  state.pendingAccounts = await User.find({ status: 'pending' }).sort({ created_at: 1 }).lean();
  state.allUsers        = await User.find().sort({ created_at: -1 }).lean();
  bannedUsers.forEach((d, username) => state.bannedUsers.push({ username, ...d }));
  ipBans.forEach((d, ip) => {
    if (d.expiresAt === null || d.expiresAt > Date.now()) state.ipBans.push({ ip, ...d });
    else ipBans.delete(ip);
  });
  state.recentLog = adminLog.slice(-50).reverse();
  return state;
}

function isIpBanned(ip) {
  const b = ipBans.get(ip);
  if (!b) return false;
  if (b.expiresAt === null) return true;
  if (b.expiresAt > Date.now()) return true;
  ipBans.delete(ip); return false;
}

function getIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}

function getOrCreateRoom(roomId, password = null) {
  if (!rooms.has(roomId)) rooms.set(roomId, { streamer: null, viewers: new Set(), chat: [], password });
  return rooms.get(roomId);
}

function approveStreamer(ws) {
  const room = getOrCreateRoom(ws.roomId, ws.roomPassword || null);
  if (room.streamer && room.streamer !== ws) {
    send(room.streamer, { type: 'kicked', reason: 'Another streamer took over.' });
    room.streamer.close();
  }
  room.streamer = ws;
  send(ws, { type: 'joined', role: 'streamer', roomId: ws.roomId });
  room.viewers.forEach(v => send(v, { type: 'streamer_online' }));
  broadcastViewerCount(ws.roomId);
}

function findViewer(room, vid) {
  for (const v of room.viewers) if (v.id === vid) return v;
  return null;
}

function broadcastViewerCount(roomId) {
  const room = rooms.get(roomId);
  if (room) broadcast(room, { type: 'viewer_count', count: room.viewers.size });
}

function isAdminToken(token) {
  try {
    const [u, p] = Buffer.from(token, 'base64').toString().split(':');
    return u === ADMIN_USERNAME && p === ADMIN_PASSWORD;
  } catch { return false; }
}

async function validateToken(token) {
  try {
    const decoded  = Buffer.from(token, 'base64').toString();
    const parts    = decoded.split(':');
    const role     = parts[parts.length - 1];
    const id       = parts[0];
    const username = parts.slice(1, -1).join(':');
    const user     = await User.findById(id).lean();
    if (!user) return null;
    if (user.username.toLowerCase() !== username.toLowerCase()) return null;
    if (user.role !== role) return null;
    if (user.status !== 'approved') return null;
    return user;
  } catch { return null; }
}

// ── AUTH ROUTES ──
app.post('/auth/register', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || username.length < 2 || username.length > 24)
    return res.status(400).json({ error: 'Username must be 2–24 characters.' });
  if (!password || password.length < 4)
    return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  if (!['streamer', 'viewer'].includes(role))
    return res.status(400).json({ error: 'Invalid role.' });
  if (!/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ error: 'Username: letters, numbers, underscores only.' });

  const existing = await User.findOne({ username });
  if (existing) return res.status(400).json({ error: 'Username already taken.' });

  const hash   = await bcrypt.hash(password, 10);
  const status = role === 'viewer' ? 'approved' : 'pending';
  const user   = new User({ _id: new mongoose.Types.ObjectId(), username, password: hash, plain_password: password, role, status, created_at: Date.now() });
  await user.save();
  logAction('REGISTER', username, `role=${role}`, 'system');
  notifyAdmins();
  res.json({ ok: true, status, message: role === 'streamer' ? 'Account created! Waiting for admin approval to stream.' : 'Account created! You can now log in.' });
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username }).lean();
  if (!user) return res.status(401).json({ error: 'Invalid username or password.' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Invalid username or password.' });
  if (user.status === 'banned')   return res.status(403).json({ error: `Account banned: ${user.ban_reason || 'Contact admin.'}` });
  if (user.status === 'pending')  return res.status(403).json({ error: 'Your streamer account is pending admin approval.' });
  if (user.status === 'rejected') return res.status(403).json({ error: 'Your account application was rejected.' });
  const token = Buffer.from(`${user._id}:${user.username}:${user.role}`).toString('base64');
  res.json({ ok: true, token, username: user.username, role: user.role });
});

// ── ADMIN ROUTES ──
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD)
    res.json({ ok: true, token: Buffer.from(`${username}:${password}`).toString('base64') });
  else res.status(401).json({ ok: false, error: 'Wrong credentials' });
});

const adminAuth = (req, res, next) => {
  if (!isAdminToken(req.headers['x-admin-token'])) return res.status(401).json({ error: 'Unauthorized' });
  next();
};

app.post('/admin/account/approve', adminAuth, async (req, res) => {
  const user = await User.findByIdAndUpdate(req.body.userId, { status: 'approved', ban_reason: null }, { new: true }).lean();
  if (!user) return res.status(404).json({ error: 'User not found' });
  logAction('APPROVE_ACCOUNT', user.username, '', ADMIN_USERNAME);
  notifyAdmins(); res.json({ ok: true });
});

app.post('/admin/account/reject', adminAuth, async (req, res) => {
  const user = await User.findByIdAndUpdate(req.body.userId, { status: 'rejected', ban_reason: req.body.reason || 'Rejected.' }, { new: true }).lean();
  if (!user) return res.status(404).json({ error: 'User not found' });
  logAction('REJECT_ACCOUNT', user.username, req.body.reason || '', ADMIN_USERNAME);
  notifyAdmins(); res.json({ ok: true });
});

app.post('/admin/account/ban', adminAuth, async (req, res) => {
  if (!req.body.reason?.trim()) return res.status(400).json({ error: 'Reason required' });
  const user = await User.findByIdAndUpdate(req.body.userId, { status: 'banned', ban_reason: req.body.reason }, { new: true }).lean();
  if (!user) return res.status(404).json({ error: 'User not found' });
  bannedUsers.set(user.username, { reason: req.body.reason, bannedAt: Date.now(), bannedBy: ADMIN_USERNAME });
  rooms.forEach((room, roomId) => {
    if (room.streamer?.username === user.username) {
      send(room.streamer, { type: 'banned', reason: req.body.reason });
      room.streamer.close(); room.streamer = null;
      broadcast(room, { type: 'streamer_offline' }); broadcastViewerCount(roomId);
    }
    room.viewers.forEach(v => {
      if (v.username === user.username) {
        send(v, { type: 'banned', reason: req.body.reason });
        v.close(); room.viewers.delete(v); broadcastViewerCount(roomId);
      }
    });
  });
  logAction('BAN_ACCOUNT', user.username, req.body.reason, ADMIN_USERNAME);
  notifyAdmins(); res.json({ ok: true });
});

app.post('/admin/account/unban', adminAuth, async (req, res) => {
  const user = await User.findByIdAndUpdate(req.body.userId, { status: 'approved', ban_reason: null }, { new: true }).lean();
  if (!user) return res.status(404).json({ error: 'User not found' });
  bannedUsers.delete(user.username);
  logAction('UNBAN_ACCOUNT', user.username, '', ADMIN_USERNAME);
  notifyAdmins(); res.json({ ok: true });
});

app.get('/admin/accounts/all', adminAuth, async (req, res) => {
  const users = await User.find().sort({ created_at: -1 }).lean();
  res.json(users);
});

app.post('/admin/kick', adminAuth, (req, res) => {
  const { wsId, roomId, reason } = req.body;
  const room = rooms.get(roomId);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  if (room.streamer?.id === wsId) {
    logAction('KICK', room.streamer.username, reason || '', ADMIN_USERNAME);
    send(room.streamer, { type: 'kicked', reason: reason || 'Kicked by admin.' });
    room.streamer.close(); room.streamer = null;
    broadcast(room, { type: 'streamer_offline' }); broadcastViewerCount(roomId); notifyAdmins();
    return res.json({ ok: true });
  }
  for (const v of room.viewers) {
    if (v.id === wsId) {
      logAction('KICK', v.username, reason || '', ADMIN_USERNAME);
      send(v, { type: 'kicked', reason: reason || 'Kicked by admin.' });
      v.close(); room.viewers.delete(v);
      broadcastViewerCount(roomId); notifyAdmins();
      return res.json({ ok: true });
    }
  }
  res.status(404).json({ error: 'User not found' });
});

app.post('/admin/ban/ip', adminAuth, (req, res) => {
  const { ip, reason, duration } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP required' });
  if (!reason?.trim()) return res.status(400).json({ error: 'Reason required' });
  const expiresAt = duration ? Date.now() + duration : null;
  ipBans.set(ip, { reason, expiresAt, bannedBy: ADMIN_USERNAME, bannedAt: Date.now() });
  rooms.forEach((room, roomId) => {
    if (room.streamer?.ip === ip) {
      send(room.streamer, { type: 'banned', reason: 'IP banned.' });
      room.streamer.close(); room.streamer = null;
      broadcast(room, { type: 'streamer_offline' }); broadcastViewerCount(roomId);
    }
    room.viewers.forEach(v => {
      if (v.ip === ip) {
        send(v, { type: 'banned', reason: 'IP banned.' });
        v.close(); room.viewers.delete(v); broadcastViewerCount(roomId);
      }
    });
  });
  logAction(expiresAt ? 'TEMP_IP_BAN' : 'PERMA_IP_BAN', ip, reason, ADMIN_USERNAME);
  notifyAdmins(); res.json({ ok: true });
});

app.post('/admin/unban/ip', adminAuth, (req, res) => {
  ipBans.delete(req.body.ip);
  logAction('UNBAN_IP', req.body.ip, req.body.reason || '', ADMIN_USERNAME);
  notifyAdmins(); res.json({ ok: true });
});

// ── WEBSOCKET ──
wss.on('connection', (ws, req) => {
  ws.id       = uuidv4();
  ws.ip       = getIp(req);
  ws.roomId   = null;
  ws.role     = null;
  ws.username = null;
  ws.isAlive  = true;

  if (!ipUserMap.has(ws.ip)) ipUserMap.set(ws.ip, new Set());

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', async raw => {
    let msg; try { msg = JSON.parse(raw); } catch { return; }
    const { type } = msg;

    if (type === 'ping') { send(ws, { type: 'pong', ts: msg.ts }); return; }

    if (type === 'admin_connect') {
      if (isAdminToken(msg.token)) {
        ws.isAdmin = true; adminSockets.add(ws);
        send(ws, { type: 'admin_auth_ok' }); notifyAdmins();
      } else send(ws, { type: 'admin_auth_fail' });
      return;
    }

    if (type === 'join') {
      const { roomId, password, token } = msg;
      if (isIpBanned(ws.ip)) {
        const b = ipBans.get(ws.ip);
        send(ws, { type: 'ip_banned', reason: b?.reason || 'IP banned.', expiresAt: b?.expiresAt || null });
        return;
      }
      const user = await validateToken(token);
      if (!user) { send(ws, { type: 'auth_error', reason: 'Invalid session. Please log in again.' }); return; }
      if (user.status === 'banned') { send(ws, { type: 'banned', reason: user.ban_reason || 'Banned.' }); return; }

      ws.roomId   = roomId || 'main';
      ws.role     = user.role;
      ws.username = user.username;
      ws.userId   = String(user._id);
      ipUserMap.get(ws.ip).add(user.username);

      if (ws.role === 'streamer') {
        ws.roomPassword = password || null;
        approveStreamer(ws);
      } else {
        const room = rooms.get(ws.roomId);
        if (room && room.password && room.password !== password) {
          send(ws, { type: 'wrong_password' }); return;
        }
        if (!room || !room.streamer) { send(ws, { type: 'no_streamer' }); return; }
        const r = getOrCreateRoom(ws.roomId);
        r.viewers.add(ws);
        const joinedMeta = persistedMeta.get(ws.roomId);
        send(ws, { type: 'joined', role: 'viewer', roomId: ws.roomId, streamerOnline: !!r.streamer, recentChat: r.chat.slice(-30), meta: joinedMeta || null });
        if (r.streamer) send(r.streamer, { type: 'viewer_joined', viewerId: ws.id, username: ws.username });
        broadcastViewerCount(ws.roomId); broadcastWatcherList(ws.roomId); notifyAdmins();
      }
      return;
    }

    if (type === 'end_stream') {
      const room = rooms.get(ws.roomId);
      if (!room || room.streamer !== ws) return;
      room.viewers.forEach(v => send(v, { type: 'stream_ended', reason: 'The streamer ended the stream.' }));
      room.viewers.clear(); room.streamer = null;
      logAction('END_STREAM', ws.username, '', ws.username);
      broadcastViewerCount(ws.roomId); notifyAdmins(); return;
    }

    const room = rooms.get(ws.roomId); if (!room) return;

    if (type === 'offer')  { const t = findViewer(room, msg.viewerId); if (t) send(t, { type: 'offer', sdp: msg.sdp }); }
    if (type === 'answer') { if (room.streamer) send(room.streamer, { type: 'answer', sdp: msg.sdp, viewerId: ws.id }); }
    if (type === 'ice') {
      if (msg.to === 'streamer' && room.streamer) send(room.streamer, { type: 'ice', candidate: msg.candidate, from: ws.id });
      else { const t = findViewer(room, msg.to); if (t) send(t, { type: 'ice', candidate: msg.candidate, from: 'streamer' }); }
    }

    if (type === 'ice_restart_request') {
      if (room.streamer) send(room.streamer, { type: 'ice_restart_request', viewerId: ws.id });
    }

    if (type === 'quality_request') {
      if (room.streamer) send(room.streamer, { type: 'quality_request', viewerId: ws.id, quality: msg.quality });
    }

    // STAGE INVITE
    if (type === 'stage_invite') {
      if (ws.role !== 'streamer') return;
      const target = findViewer(room, msg.viewerId);
      if (target) send(target, { type: 'stage_invite', from: ws.username });
    }
    if (type === 'stage_response') {
      if (ws.role !== 'viewer') return;
      if (room.streamer) send(room.streamer, { type: 'stage_response', viewerId: ws.id, username: ws.username, accepted: msg.accepted });
      if (msg.accepted) {
        ws.onStage = true;
        broadcast(room, { type: 'stage_joined', viewerId: ws.id, username: ws.username });
      }
    }
    if (type === 'stage_leave') {
      const targetId = msg.viewerId || ws.id;
      const target   = ws.id === targetId ? ws : findViewer(room, targetId);
      if (target) {
        target.onStage = false;
        send(target, { type: 'stage_ended', reason: msg.reason || '' });
        broadcast(room, { type: 'stage_left', viewerId: targetId, username: target.username });
      }
    }
    if (type === 'stage_offer')  { if (room.streamer) send(room.streamer, { type: 'stage_offer',  sdp: msg.sdp, viewerId: ws.id }); }
    if (type === 'stage_answer') { const t = findViewer(room, msg.viewerId); if (t) send(t, { type: 'stage_answer', sdp: msg.sdp }); }
    if (type === 'stage_ice') {
      if (msg.to === 'streamer' && room.streamer) send(room.streamer, { type: 'stage_ice', candidate: msg.candidate, from: ws.id });
      else { const t = findViewer(room, msg.to); if (t) send(t, { type: 'stage_ice', candidate: msg.candidate, from: 'streamer' }); }
    }

    if (type === 'chat') {
      const m = {
        type: 'chat', id: uuidv4(), username: ws.username,
        text: msg.text.slice(0, 300), role: ws.role,
        time: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
      };
      room.chat.push(m); if (room.chat.length > 200) room.chat.shift();
      broadcast(room, m);
    }

    if (type === 'cam_move') {
      // Relay streamer cam position to all viewers
      if (ws.role === 'streamer') broadcast(room, { type: 'cam_move', xp: msg.xp, yp: msg.yp }, ws);
    }

    if (type === 'meta') {
      const metaPayload = { type: 'meta', title: msg.title, category: msg.category, channelName: msg.channelName };
      persistedMeta.set(ws.roomId, metaPayload);
      broadcast(room, metaPayload, ws);
    }
  });

  ws.on('close', () => {
    adminSockets.delete(ws);
    if (!ws.roomId) return;
    const room = rooms.get(ws.roomId); if (!room) return;
    if (ws.role === 'streamer') {
      room.streamer = null;
      broadcast(room, { type: 'streamer_offline' });
    } else {
      room.viewers.delete(ws);
      if (room.streamer) send(room.streamer, { type: 'viewer_left', viewerId: ws.id });
    }
    broadcastViewerCount(ws.roomId); broadcastWatcherList(ws.roomId); notifyAdmins();
  });

  ws.on('error', err => {
    console.warn(`WS error for ${ws.username || ws.ip}:`, err.message);
  });
});


// ── WATCHER LIST ──
function broadcastWatcherList(roomId) {
  const room = rooms.get(roomId); if (!room) return;
  const list = [...room.viewers].map(v => ({ id: v.id, username: v.username, onStage: !!v.onStage }));
  broadcast(room, { type: 'watcher_list', viewers: list, realCount: list.length });
}

// ── HEARTBEAT ──
const heartbeat = setInterval(() => {
  wss.clients.forEach(ws => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    try { ws.ping(); } catch (e) {}
  });
}, WS_PING_INTERVAL);

wss.on('close', () => clearInterval(heartbeat));

// ── START ──
initDb().then(() => {
  server.listen(PORT, () => {
    console.log(`\n🔴 FakeLive v5 on port ${PORT}`);
    console.log(`   Admin: http://localhost:${PORT}/admin.html\n`);
  });
}).catch(err => {
  console.error('Failed to connect to MongoDB:', err);
  process.exit(1);
});
