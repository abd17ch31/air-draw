const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;

// =========================================================
// 🔐 PASSWORD (hashed)
// =========================================================
// Plaintext default: "airdraw2025"
// To change: run  node -e "console.log(require('crypto').createHash('sha256').update('YOUR_PASSWORD').digest('hex'))"
// then paste the output below (or set ROOM_PASSWORD_HASH env var).
const ROOM_PASSWORD_HASH = process.env.ROOM_PASSWORD_HASH
  || '502fb41dde6d98474b8141b81db82494bc62cd7071e45880b5b21065a2d4acca';

function hashPassword(plain) {
  return crypto.createHash('sha256').update(String(plain || '')).digest('hex');
}

function checkPassword(plain) {
  try {
    const a = Buffer.from(hashPassword(plain), 'hex');
    const b = Buffer.from(ROOM_PASSWORD_HASH, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

// =========================================================
// 🚦 RATE LIMITER (per IP)
// =========================================================
const RATE_WINDOW_MS  = 60 * 1000; // 1 minute
const RATE_MAX_FAILS  = 5;         // after 5 wrong passwords in window
const RATE_BLOCK_MS   = 5 * 60 * 1000; // block for 5 minutes

const rateBuckets = new Map(); // ip -> { fails, windowStart, blockedUntil }

function getClientIp(req) {
  // Behind ngrok / proxies: X-Forwarded-For is a comma-separated list
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function isRateLimited(ip) {
  const now = Date.now();
  let b = rateBuckets.get(ip);
  if (!b) return false;
  if (b.blockedUntil && now < b.blockedUntil) return true;
  return false;
}

function recordFailure(ip) {
  const now = Date.now();
  let b = rateBuckets.get(ip);
  if (!b || now - b.windowStart > RATE_WINDOW_MS) {
    b = { fails: 0, windowStart: now, blockedUntil: 0 };
  }
  b.fails++;
  if (b.fails >= RATE_MAX_FAILS) {
    b.blockedUntil = now + RATE_BLOCK_MS;
    console.log(`[security] IP ${ip} blocked for 5 min after ${b.fails} failed attempts`);
  }
  rateBuckets.set(ip, b);
}

function recordSuccess(ip) {
  rateBuckets.delete(ip);
}

// Periodic cleanup of stale buckets
setInterval(() => {
  const now = Date.now();
  for (const [ip, b] of rateBuckets) {
    const expired = (!b.blockedUntil && now - b.windowStart > RATE_WINDOW_MS)
                 || ( b.blockedUntil && now > b.blockedUntil + RATE_WINDOW_MS);
    if (expired) rateBuckets.delete(ip);
  }
}, 60 * 1000);

// =========================================================
// 🧹 ROOM NAME SANITIZER
// =========================================================
function sanitizeRoom(r) {
  if (typeof r !== 'string') return 'default';
  const clean = r.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 32);
  return clean || 'default';
}

// =========================================================
// 🌐 STATIC FILE SERVER
// =========================================================
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'text/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.webmanifest': 'application/manifest+json'
};

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(self), microphone=(self)',
  'Content-Security-Policy':
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://storage.googleapis.com; " +
    "style-src 'self' 'unsafe-inline'; " +
    "connect-src 'self' wss: https:; " +
    "img-src 'self' data: blob:; " +
    "media-src 'self' blob:; " +
    "frame-ancestors 'none';"
};



const server = http.createServer((req, res) => {
  let urlPath = decodeURIComponent(req.url.split('?')[0]);
  if (urlPath === '/') urlPath = '/index.html';

  const filePath = path.join(__dirname, urlPath);
  if (!filePath.startsWith(__dirname)) {
    res.writeHead(403, SECURITY_HEADERS); res.end('Forbidden'); return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain' });
      res.end('Not found'); return;
    }
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'Content-Type': MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
      'Cache-Control': 'no-cache'
    });
    res.end(data);
  });
});

// =========================================================
// 🔌 WEBSOCKET SIGNALING (with size limit + keepalive)
// =========================================================
const wss = new WebSocketServer({
  server,
  maxPayload: 64 * 1024   // 64 KB max per message — plenty for strokes + chat
});

// Keepalive heartbeat
const HEARTBEAT_MS = 25000;
const heartbeatInterval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  });
}, HEARTBEAT_MS);

wss.on('close', () => clearInterval(heartbeatInterval));

const rooms = new Map();

wss.on('connection', (ws, req) => {
  ws.roomId  = null;
  ws.peerId  = crypto.randomBytes(4).toString('hex');
  ws.authed  = false;
  ws.isAlive = true;
  ws.ip      = getClientIp(req);

  ws.on('pong', () => { ws.isAlive = true; });

  console.log(`[ws] connected peer=${ws.peerId} ip=${ws.ip}`);

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // ---- Application-level keepalive ----
    if (msg.type === 'ping') {
      try { ws.send(JSON.stringify({ type: 'pong' })); } catch {}
      return;
    }

    // ---- JOIN (password auth) ----
    if (msg.type === 'join') {
      // Rate limit check FIRST
      if (isRateLimited(ws.ip)) {
        ws.send(JSON.stringify({
          type: 'error',
          message: 'Too many failed attempts. Try again in 5 minutes.'
        }));
        ws.close();
        return;
      }

      if (!checkPassword(msg.password)) {
        recordFailure(ws.ip);
        console.log(`[security] wrong password from ip=${ws.ip}`);
        ws.send(JSON.stringify({ type: 'error', message: 'Wrong password' }));
        ws.close();
        return;
      }

      recordSuccess(ws.ip);
      ws.authed = true;

      const roomId = sanitizeRoom(msg.room);
      if (!rooms.has(roomId)) rooms.set(roomId, new Set());
      const room = rooms.get(roomId);

      if (room.size >= 2) {
        ws.send(JSON.stringify({ type: 'error', message: 'Room is full' }));
        ws.close();
        return;
      }

      ws.roomId = roomId;
      room.add(ws);
      console.log(`[ws] peer ${ws.peerId} joined "${roomId}" (${room.size}/2)`);

      const peers = [...room];
      peers.forEach((peer, i) => {
        peer.send(JSON.stringify({
          type: 'joined',
          peerCount: peers.length,
          isInitiator: i === 1
        }));
      });
    }

    // ---- SIGNAL relay ----
    if (msg.type === 'signal') {
      if (!ws.authed) return;
      const room = rooms.get(ws.roomId);
      if (!room) return;
      for (const peer of room) {
        if (peer !== ws && peer.readyState === 1) {
          peer.send(JSON.stringify({ type: 'signal', data: msg.data }));
        }
      }
    }
  });

  ws.on('close', () => {
    const room = rooms.get(ws.roomId);
    if (!room) return;
    room.delete(ws);
    console.log(`[ws] peer ${ws.peerId} left "${ws.roomId}" (${room.size}/2)`);
    if (room.size === 0) rooms.delete(ws.roomId);
    else for (const peer of room) peer.send(JSON.stringify({ type: 'peerLeft' }));
  });

  ws.on('error', (err) => {
    console.warn(`[ws] error from ${ws.peerId}:`, err.message);
  });
});

// =========================================================
// 🚀 START
// =========================================================
server.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`🔐 Room password: hashed (SHA-256, timing-safe compare)`);
  console.log(`🚦 Rate limit: ${RATE_MAX_FAILS} failed attempts per ${RATE_WINDOW_MS/1000}s → ${RATE_BLOCK_MS/60000} min block`);
  console.log(`📦 Max WS payload: 64 KB`);
  console.log(`🛡️  Security headers: CSP, nosniff, DENY frames, permissions policy`);
  console.log(`💡 To change password, run:`);
  console.log(`   node -e "console.log(require('crypto').createHash('sha256').update('NEW_PASSWORD').digest('hex'))"`);
  console.log(`   then paste the hash into ROOM_PASSWORD_HASH in server.js`);
});
