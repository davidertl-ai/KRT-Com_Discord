'use strict';

const { WebSocketServer } = require('ws');
const crypto = require('crypto');
const { verifyToken, hashUserId } = require('./crypto');

/**
 * Voice Relay
 * - Companion clients connect via WebSocket to /voice for control signaling
 *   (auth, join/leave frequency, heartbeat)
 * - Opus audio is exchanged as binary WebSocket frames
 * - Packet format: [4 bytes freqId BE][4 bytes sequence BE][opus data]
 */
function createVoiceRelay({ db, usersStore, allowedGuildIds = [], tokenSecret = '', dsgvo = null }) {
  // Session management
  const sessions = new Map();       // sessionToken -> { discordUserId, guildId, displayName, ws, frequencies: Set, lastSeen }

  // Frequency subscriptions: freqId -> Set<sessionToken>
  const freqSubscribers = new Map();

  // Per-frequency AES-256 encryption keys (E2E audio encryption)
  // freqId -> Buffer (32 bytes). Generated on first join, deleted when last subscriber leaves.
  const freqKeys = new Map();

  // Clean up stale DB rows from a previous crash/restart
  db.prepare('DELETE FROM freq_listeners').run();
  db.prepare('DELETE FROM voice_sessions').run();
  console.log('[voice] Cleaned stale DB sessions on startup');

  const wss = new WebSocketServer({ noServer: true });

  function start() {

    wss.on('connection', (ws, req) => {
      let sessionToken = null;

      ws.on('message', (raw, isBinary) => {
        // Binary = audio frame
        if (isBinary) {
          if (sessionToken) handleAudio(sessionToken, raw);
          return;
        }

        // Text = control message
        let msg;
        try { msg = JSON.parse(raw); } catch { return; }

        switch (msg.type) {
          case 'auth':
            handleAuth(ws, msg, (token) => { sessionToken = token; });
            break;
          case 'join':
            if (sessionToken) handleJoin(sessionToken, msg);
            break;
          case 'leave':
            if (sessionToken) handleLeave(sessionToken, msg);
            break;
          case 'mute':
            if (sessionToken) handleMute(sessionToken, msg);
            break;
          case 'unmute':
            if (sessionToken) handleUnmute(sessionToken, msg);
            break;
          case 'ping':
            if (sessionToken) {
              const s = sessions.get(sessionToken);
              if (s) s.lastSeen = Date.now();
              ws.send(JSON.stringify({ type: 'pong' }));
            }
            break;
        }
      });

      ws.on('close', () => {
        if (sessionToken) cleanupSession(sessionToken);
      });

      ws.on('error', () => {
        if (sessionToken) cleanupSession(sessionToken);
      });
    });

    // Periodic cleanup of stale sessions (no heartbeat for > 60s)
    setInterval(() => {
      const cutoff = Date.now() - 60000;
      for (const [token, session] of sessions) {
        if (session.lastSeen < cutoff) {
          console.log('[voice] Cleaning up stale session:', session.discordUserId);
          if (session.ws && session.ws.readyState <= 1) {
            session.ws.close(4000, 'timeout');
          }
          cleanupSession(token);
        }
      }
    }, 30000);
  }

  // --- Audio handling (binary WS frames) ---
  function handleAudio(senderToken, buf) {
    if (buf.length < 9) return; // min: 4 freqId + 4 seq + 1 byte opus

    const freqId = buf.readUInt32BE(0);

    const senderSession = sessions.get(senderToken);
    if (!senderSession) return;

    // Verify sender is subscribed to this frequency
    if (!senderSession.frequencies.has(freqId)) return;

    const subscribers = freqSubscribers.get(freqId);
    if (!subscribers) return;

    // Forward audio to all other subscribers as binary WS frame
    for (const subToken of subscribers) {
      if (subToken === senderToken) continue;
      const sub = sessions.get(subToken);
      if (!sub || !sub.ws || sub.ws.readyState !== 1) continue;
      // Skip if receiver has muted this frequency
      if (sub.mutedFreqs.has(freqId)) continue;
      sub.ws.send(buf);
    }
  }

  function handleAuth(ws, msg, setToken) {
    const { discordUserId, guildId, authToken } = msg;

    let resolvedUserId = discordUserId;
    let resolvedGuildId = guildId;
    let resolvedDisplayName = null;

    // Token-based auth (preferred): verify signed token from /auth/login
    if (authToken && tokenSecret) {
      const payload = verifyToken(authToken, tokenSecret);
      if (!payload) {
        ws.send(JSON.stringify({ type: 'auth_error', reason: 'invalid or expired token' }));
        return;
      }
      resolvedUserId = payload.uid;
      resolvedGuildId = payload.gid;
      resolvedDisplayName = payload.name;
    }

    if (!resolvedUserId || !resolvedGuildId) {
      ws.send(JSON.stringify({ type: 'auth_error', reason: 'missing credentials' }));
      return;
    }

    // When no signed token was used, the resolvedUserId is a raw Discord snowflake.
    // Hash it so all downstream code (sessions, DB, ban checks) uses the hashed form.
    // When a signed token WAS used, payload.uid is already hashed.
    if (!(authToken && tokenSecret)) {
      resolvedUserId = hashUserId(String(resolvedUserId));
    }

    // Check allowed guilds
    if (allowedGuildIds.length > 0 && !allowedGuildIds.includes(String(resolvedGuildId))) {
      ws.send(JSON.stringify({ type: 'auth_error', reason: 'guild not allowed' }));
      return;
    }

    // Check if banned
    if (dsgvo && typeof dsgvo.isBanned === 'function' && dsgvo.isBanned(String(resolvedUserId))) {
      ws.send(JSON.stringify({ type: 'auth_error', reason: 'access denied' }));
      return;
    }

    // Look up user (skip if token already provided display name)
    const user = usersStore ? usersStore.get(String(resolvedUserId), String(resolvedGuildId)) : null;
    if (!user && !resolvedDisplayName) {
      ws.send(JSON.stringify({ type: 'auth_error', reason: 'user not found in guild' }));
      return;
    }

    // Generate session token
    const sessionToken = crypto.randomBytes(24).toString('hex');
    const now = Date.now();

    const displayName = resolvedDisplayName || (user ? user.display_name : null) || String(resolvedUserId);
    const session = {
      discordUserId: String(resolvedUserId),
      guildId: String(resolvedGuildId),
      displayName,
      ws,
      frequencies: new Set(),
      mutedFreqs: new Set(),   // freqIds where this user is RX-muted (server won't forward audio)
      lastSeen: now,
    };
    // Concurrent session limit: max 3 per user
    const MAX_SESSIONS_PER_USER = 3;
    let userSessionCount = 0;
    for (const [, s] of sessions) {
      if (s.discordUserId === session.discordUserId) userSessionCount++;
    }
    if (userSessionCount >= MAX_SESSIONS_PER_USER) {
      ws.send(JSON.stringify({ type: 'auth_error', reason: 'too many concurrent sessions' }));
      return;
    }

    sessions.set(sessionToken, session);
    setToken(sessionToken);

    // Persist session (hash the session token before storing in DB)
    const hashedSessionToken = crypto.createHash('sha256').update(sessionToken).digest('hex');
    db.prepare(
      'INSERT OR REPLACE INTO voice_sessions (session_token, discord_user_id, guild_id, display_name, created_at_ms, last_seen_ms) VALUES (?,?,?,?,?,?)'
    ).run(hashedSessionToken, session.discordUserId, session.guildId, session.displayName, now, now);

    console.log('[voice] Auth OK:', session.discordUserId, session.displayName);

    ws.send(JSON.stringify({
      type: 'auth_ok',
      sessionToken,
      displayName: session.displayName,
    }));
  }

  function handleJoin(sessionToken, msg) {
    const session = sessions.get(sessionToken);
    if (!session) return;

    const freqId = Number(msg.freqId);
    if (!Number.isInteger(freqId) || freqId < 1000 || freqId > 9999) {
      session.ws.send(JSON.stringify({ type: 'join_error', reason: 'bad freqId' }));
      return;
    }

    session.frequencies.add(freqId);
    if (!freqSubscribers.has(freqId)) freqSubscribers.set(freqId, new Set());
    freqSubscribers.get(freqId).add(sessionToken);

    // Generate per-frequency E2E encryption key if this is the first subscriber
    if (!freqKeys.has(freqId)) {
      freqKeys.set(freqId, crypto.randomBytes(32));
      console.log('[voice] Generated E2E key for freq', freqId);
    }
    const freqKeyB64 = freqKeys.get(freqId).toString('base64');

    // Persist to freq_listeners DB
    db.prepare(
      'INSERT OR REPLACE INTO freq_listeners (discord_user_id, freq_id, radio_slot, connected_at_ms) VALUES (?,?,?,?)'
    ).run(session.discordUserId, freqId, 0, Date.now());

    console.log('[voice] Join freq', freqId, 'by', session.discordUserId);

    const listenerCount = freqSubscribers.get(freqId).size;

    session.ws.send(JSON.stringify({
      type: 'join_ok',
      freqId,
      listenerCount,
      freqKey: freqKeyB64,
    }));

    // Notify other subscribers about updated listener count
    for (const subToken of freqSubscribers.get(freqId)) {
      if (subToken === sessionToken) continue;
      const sub = sessions.get(subToken);
      if (sub && sub.ws && sub.ws.readyState === 1) {
        sub.ws.send(JSON.stringify({ type: 'listener_update', freqId, listenerCount }));
      }
    }
  }

  function handleLeave(sessionToken, msg) {
    const session = sessions.get(sessionToken);
    if (!session) return;

    const freqId = Number(msg.freqId);
    session.frequencies.delete(freqId);

    const subs = freqSubscribers.get(freqId);
    if (subs) {
      subs.delete(sessionToken);
      if (subs.size === 0) {
        freqSubscribers.delete(freqId);
        // Delete E2E key when no subscribers remain (forward secrecy)
        if (freqKeys.has(freqId)) {
          freqKeys.delete(freqId);
          console.log('[voice] Deleted E2E key for freq', freqId, '(no subscribers)');
        }
      }
    }

    // Remove from freq_listeners DB
    db.prepare('DELETE FROM freq_listeners WHERE discord_user_id = ? AND freq_id = ?').run(session.discordUserId, freqId);

    console.log('[voice] Leave freq', freqId, 'by', session.discordUserId);

    session.ws.send(JSON.stringify({
      type: 'leave_ok',
      freqId,
    }));

    // Notify remaining subscribers about updated listener count
    const remainingSubs = freqSubscribers.get(freqId);
    if (remainingSubs) {
      const listenerCount = remainingSubs.size;
      for (const subToken of remainingSubs) {
        const sub = sessions.get(subToken);
        if (sub && sub.ws && sub.ws.readyState === 1) {
          sub.ws.send(JSON.stringify({ type: 'listener_update', freqId, listenerCount }));
        }
      }
    }
  }

  function handleMute(sessionToken, msg) {
    const session = sessions.get(sessionToken);
    if (!session) return;

    const freqId = Number(msg.freqId);
    if (!Number.isInteger(freqId) || freqId < 1000 || freqId > 9999) {
      session.ws.send(JSON.stringify({ type: 'mute_error', reason: 'bad freqId' }));
      return;
    }

    session.mutedFreqs.add(freqId);
    console.log('[voice] Mute freq', freqId, 'by', session.discordUserId);

    session.ws.send(JSON.stringify({
      type: 'mute_ok',
      freqId,
      muted: true,
    }));
  }

  function handleUnmute(sessionToken, msg) {
    const session = sessions.get(sessionToken);
    if (!session) return;

    const freqId = Number(msg.freqId);
    if (!Number.isInteger(freqId) || freqId < 1000 || freqId > 9999) {
      session.ws.send(JSON.stringify({ type: 'mute_error', reason: 'bad freqId' }));
      return;
    }

    session.mutedFreqs.delete(freqId);
    console.log('[voice] Unmute freq', freqId, 'by', session.discordUserId);

    session.ws.send(JSON.stringify({
      type: 'mute_ok',
      freqId,
      muted: false,
    }));
  }

  function cleanupSession(token) {
    if (!sessions.has(token)) return;
    const session = sessions.get(token);
    if (!session) return;

    // Remove from all frequency subscriptions and notify remaining subscribers
    for (const freqId of session.frequencies) {
      const subs = freqSubscribers.get(freqId);
      if (subs) {
        subs.delete(token);
        // Notify remaining subscribers about updated listener count
        if (subs.size > 0) {
          const listenerCount = subs.size;
          for (const subToken of subs) {
            const sub = sessions.get(subToken);
            if (sub && sub.ws && sub.ws.readyState === 1) {
              sub.ws.send(JSON.stringify({ type: 'listener_update', freqId, listenerCount }));
            }
          }
        } else {
          freqSubscribers.delete(freqId);
          // Delete E2E key when no subscribers remain (forward secrecy)
          if (freqKeys.has(freqId)) {
            freqKeys.delete(freqId);
            console.log('[voice] Deleted E2E key for freq', freqId, '(no subscribers)');
          }
        }
      }
    }

    // Remove all freq_listeners for this user
    db.prepare('DELETE FROM freq_listeners WHERE discord_user_id = ?').run(session.discordUserId);

    // Remove DB session (hash token to match stored hash)
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    db.prepare('DELETE FROM voice_sessions WHERE session_token = ?').run(hashedToken);

    sessions.delete(token);
    console.log('[voice] Session cleaned up:', session.discordUserId);
  }

  /**
   * Notify voice relay subscribers about a TX event (from REST API).
   * Sends an 'rx' message to all subscribers on the frequency except the transmitter.
   */
  function notifyTxEvent(payload) {
    const freqId = Number(payload.freqId);
    const discordUserId = String(payload.discordUserId || '');
    const action = payload.action;

    const subs = freqSubscribers.get(freqId);
    if (!subs || subs.size === 0) return;

    // Look up sender's display name from their session
    let username = discordUserId;
    for (const [, session] of sessions) {
      if (session.discordUserId === discordUserId) {
        username = session.displayName || username;
        break;
      }
    }

    const msg = JSON.stringify({
      type: 'rx',
      freqId,
      discordUserId,
      username,
      action,
    });

    for (const subToken of subs) {
      const sub = sessions.get(subToken);
      if (!sub || !sub.ws || sub.ws.readyState !== 1) continue;
      if (sub.discordUserId === discordUserId) continue; // don't echo to sender
      sub.ws.send(msg);
    }

    // On TX stop, broadcast updated listener count to ALL subscribers (including sender)
    // so everyone sees the correct count after a transmission ends
    if (action === 'stop') {
      const listenerCount = subs.size;
      const luMsg = JSON.stringify({ type: 'listener_update', freqId, listenerCount });
      for (const subToken of subs) {
        const sub = sessions.get(subToken);
        if (sub && sub.ws && sub.ws.readyState === 1) {
          sub.ws.send(luMsg);
        }
      }
    }
  }

  /**
   * Kick a user by their hashed Discord ID.
   * Closes all active WebSocket connections and cleans up sessions.
   */
  function kickUser(hashedUserId) {
    let kicked = 0;
    for (const [token, session] of sessions) {
      if (session.discordUserId === hashedUserId) {
        console.log(`[voice] Kicking user ${hashedUserId.substring(0, 12)}... (ban)`);
        if (session.ws && session.ws.readyState <= 1) {
          session.ws.close(4003, 'banned');
        }
        cleanupSession(token);
        kicked++;
      }
    }
    return kicked;
  }

  return {
    start,
    wss,
    notifyTxEvent,
    kickUser,
    handleUpgrade: (req, socket, head) => {
      wss.handleUpgrade(req, socket, head, (ws) => {
        wss.emit('connection', ws, req);
      });
    },
  };
}

module.exports = { createVoiceRelay };