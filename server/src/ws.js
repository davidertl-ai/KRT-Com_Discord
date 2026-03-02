'use strict';

const WebSocket = require('ws');

function createWsHub({ stateStore, tokenSecret }) {
  const wss = new WebSocket.Server({ noServer: true });

  function send(ws, obj) {
    if (ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify(obj));
  }

  wss.on('connection', (ws, req) => {
    // Authenticate: require valid token in query string
    try {
      const url = new URL(req.url, 'http://localhost');
      const token = url.searchParams.get('token');
      if (!token) { ws.close(4001, 'Missing token'); return; }
      const { verifyToken } = require('./crypto');
      const payload = verifyToken(token, tokenSecret);
      if (!payload) { ws.close(4001, 'Invalid token'); return; }
      ws.userId = payload.uid;
    } catch (e) {
      ws.close(4001, 'Auth failed');
      return;
    }

    // Snapshot: voice_state
    const recent = stateStore.listRecent(200);
    send(ws, { type: 'snapshot', payload: recent });

    ws.on('message', (buf) => {
      try {
        const msg = JSON.parse(buf.toString('utf-8'));
        if (msg?.type === 'ping') send(ws, { type: 'pong', ts: Date.now() });
      } catch (_) {}
    });
  });

  return {
    wss,
    handleUpgrade: (req, socket, head) => {
      wss.handleUpgrade(req, socket, head, (ws) => {
        wss.emit('connection', ws, req);
      });
    },
    broadcast: (obj) => {
      const msg = JSON.stringify(obj);
      for (const ws of wss.clients) {
        if (ws.readyState === WebSocket.OPEN) ws.send(msg);
      }
    },
  };
}

module.exports = { createWsHub };