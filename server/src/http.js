'use strict';

const express = require('express');
const http = require('http');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

function createHttpServer({ db, mapping, stateStore, txStore, usersStore, dsgvo, bot, adminToken, allowedGuildIds, tokenSecret, policyVersion, policyText, discordClientId, discordClientSecret, discordRedirectUri, appVersion }) {
  let _voiceRelay = null;
  const app = express();
  app.use(express.json());

  // Security headers
  app.use(helmet());

  // CORS policy: reject requests from browsers (desktop app sends no Origin)
  app.use(cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true); // no Origin = non-browser client
      cb(new Error('Browser requests not allowed'));
    }
  }));

  // Global rate limiter
  const globalLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false });
  app.use(globalLimiter);

  // Auth-specific rate limiter (stricter: 20 requests per 15 min)
  const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });

  // Trust exactly one proxy hop (Traefik) -> makes req.protocol read X-Forwarded-Proto
  // securely, ignoring forged headers from direct client connections
  app.set('trust proxy', 1);

  // DSGVO HTTPS enforcement: when DSGVO compliance mode is enabled,
  // reject any request that did not arrive via HTTPS (through Traefik).
  // Exemptions: /health, /server-status, /privacy-policy (public, no user data),
  // and loopback connections (service.sh admin CLI).
  app.use((req, res, next) => {
    // Public/info endpoints | no user data, always allowed
    if (req.path === '/health' || req.path === '/server-status' || req.path === '/privacy-policy') return next();
    // Allow localhost connections (service.sh admin CLI)
    const remoteIp = req.ip || req.connection.remoteAddress || '';
    if (remoteIp === '127.0.0.1' || remoteIp === '::1' || remoteIp === '::ffff:127.0.0.1') return next();
    if (dsgvo && typeof dsgvo.getStatus === 'function') {
      const status = dsgvo.getStatus();
      if (status.dsgvoEnabled && req.protocol !== 'https') {
        return res.status(403).json({
          ok: false,
          error: 'HTTPS required | DSGVO compliance mode is active. Connect via https:// through the reverse proxy.'
        });
      }
    }
    next();
  });

  const { signToken, verifyToken, hashUserId } = require('./crypto');

  let onTxEventFn = null;
  let _bot = bot;

  // In-memory pending OAuth states: state -> { status: 'pending'|'success'|'error', timestamp, ...data }
  const pendingOAuth = new Map();
  // Cleanup old pending states every 5 minutes
  setInterval(() => {
    const now = Date.now();
    for (const [state, entry] of pendingOAuth) {
      if (entry && entry.timestamp < now - 5 * 60 * 1000) {
        pendingOAuth.delete(state);
      }
    }
  }, 5 * 60 * 1000);

  app.get('/health', (req, res) => res.json({ ok: true }));

  // --- Public endpoints (no auth required) ---

  // Server status: version, DSGVO mode, debug mode, policy version, OAuth URL
  app.get('/server-status', (req, res) => {
    const status = dsgvo ? dsgvo.getStatus() : {};
    const oauthConfigured = !!(discordClientId && discordClientSecret && discordRedirectUri);
    res.json({
      ok: true,
      data: {
        version: appVersion,
        dsgvoEnabled: status.dsgvoEnabled || false,
        debugMode: status.debugMode || false,
        retentionDays: status.retentionDays || 0,
        policyVersion: policyVersion || '1.0',
        oauthEnabled: oauthConfigured,
      },
    });
  });

  // Privacy policy text
  app.get('/privacy-policy', (req, res) => {    const status = dsgvo ? dsgvo.getStatus() : {};
    const oauthConfigured = !!(discordClientId && discordClientSecret && discordRedirectUri);
    res.json({
      ok: true,
      data: {
        version: policyVersion || '1.0',
        text: policyText || 'No privacy policy configured on this server.',
      },
    });
  });

  // --- Auth endpoints ---

  // Login: verify user exists in guild, issue signed token
  // SECURITY: Only available in debug mode | use Discord OAuth2 for production login
  app.post('/auth/login', authLimiter, async (req, res) => {
    const debugActive = dsgvo ? dsgvo.getStatus().debugMode : false;
    if (!debugActive) {
      return res.status(410).json({ ok: false, error: 'direct_login_disabled', message: 'Direct login is disabled. Use Discord OAuth2 to log in. Enable debug mode via service.sh to re-enable.' });
    }
    const { discordUserId, guildId } = req.body || {};
    if (!discordUserId || !guildId) {
      return res.status(400).json({ ok: false, error: 'missing discordUserId or guildId' });
    }

    // Hash the raw Discord ID | raw IDs are never stored
    const hashedId = hashUserId(String(discordUserId));

    // Check if banned
    if (dsgvo && typeof dsgvo.isBanned === 'function' && dsgvo.isBanned(hashedId)) {
      return res.status(403).json({ ok: false, error: 'access denied' });
    }

    // Look up user in local cache
    let user = usersStore ? usersStore.get(hashedId, String(guildId)) : null;
    if (!user) {
      // Fallback: live Discord API lookup via bot (not dsgvo)
      if (_bot && typeof _bot.fetchGuildMember === 'function') {
        const fetched = await _bot.fetchGuildMember(String(discordUserId), String(guildId));
        if (fetched) {
          user = { display_name: fetched.nickname || fetched.displayName || fetched.user?.username };
        }
      }

      if (!user) {
        return res.status(404).json({ ok: false, error: 'user not found in guild' });
      }
    }

    // Check policy acceptance
    const pv = policyVersion || '1.0';
    const policyAccepted = dsgvo ? dsgvo.hasPolicyAcceptance(hashedId, pv) : true;

    // Issue signed token (uid is the hashed ID)
    const authPayload = {
      uid: hashedId,
      gid: String(guildId),
      name: user.display_name || hashedId.substring(0, 12) + '...',
      iat: Date.now(),
      exp: Date.now() + 24 * 60 * 60 * 1000,
    };
    const authToken = signToken(authPayload, tokenSecret);

    // Store token in DB (hashed user ID) | remove old tokens for this user first
    db.prepare('DELETE FROM auth_tokens WHERE discord_user_id = ?').run(hashedId);
    db.prepare(
      'INSERT INTO auth_tokens (token_id, discord_user_id, guild_id, display_name, created_at_ms, expires_at_ms) VALUES (?,?,?,?,?,?)'
    ).run(authToken.substring(0, 64), hashedId, String(guildId), authPayload.name, authPayload.iat, authPayload.exp);

    res.json({ ok: true, data: { token: authToken, displayName: authPayload.name, policyVersion: pv, policyAccepted } });
  });
  // Accept privacy policy
  app.post('/auth/accept-policy', (req, res) => {
    const authHeader = req.header('authorization') || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!token || !tokenSecret) {
      return res.status(401).json({ ok: false, error: 'unauthorized' });
    }
    const payload = verifyToken(token, tokenSecret);

    if (!payload) {
      return res.status(401).json({ ok: false, error: 'invalid or expired token' });
    }
    const { version } = req.body || {};
    const pv = version || policyVersion || '1.0';
    if (dsgvo && typeof dsgvo.acceptPolicy === 'function') {
      dsgvo.acceptPolicy(payload.uid, pv);
    }

    res.json({ ok: true, data: { accepted: true, version: pv } });
  });

  // --- Discord OAuth2 endpoints ---

  // Step 1: Companion app opens this URL in browser â redirects to Discord authorize
  app.get('/auth/discord/redirect', authLimiter, (req, res) => {
    const { state } = req.query;
    if (!state) return res.status(400).send('Missing state parameter');
    if (!discordClientId || !discordRedirectUri) {
      return res.status(500).send('Discord OAuth2 not configured on this server');
    }
    // Register state so the callback can find it later
    pendingOAuth.set(state, { status: 'pending', timestamp: Date.now() });
    const scope = 'identify guilds';
    let url = 'https://discord.com/oauth2/authorize?response_type=code';
    url += '&client_id=' + encodeURIComponent(discordClientId);
    url += '&scope=' + encodeURIComponent(scope);
    url += '&state=' + encodeURIComponent(state);
    url += '&redirect_uri=' + encodeURIComponent(discordRedirectUri);
    url += '&prompt=consent';
    res.redirect(url);
  });

  // Step 2: Discord redirects here after user authorizes â exchange code â issue token
  app.get('/auth/discord/callback', async (req, res) => {
    const { code, state } = req.query;
    if (!code || !state) return res.status(400).send('Missing code or state');
    if (!pendingOAuth.has(state)) return res.status(400).send('Unknown or expired state');

    try {
      const tokenResp = await fetch('https://discord.com/api/v10/oauth2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: discordClientId,
          client_secret: discordClientSecret,
          grant_type: 'authorization_code',
          code: String(code),
          redirect_uri: discordRedirectUri,
        }),
      });
      const tokenData = await tokenResp.json();
      const discordAccessToken = tokenData.access_token;
      if (!discordAccessToken) {
        console.error('[oauth] Token exchange failed:', tokenData);
        pendingOAuth.set(state, { status: 'error', error: 'server_error', timestamp: Date.now() });
        return res.status(500).send('<html><body style="background:#1a1a2e;color:#ff4a4a;font-family:sans-serif;text-align:center;padding:60px"><h2>Login Failed</h2><p>Token exchange with Discord failed.</p><p style="color:#888">You can close this window.</p></body></html>');
      }
      const userResp = await fetch('https://discord.com/api/v10/users/@me', {
        headers: { Authorization: 'Bearer ' + discordAccessToken },
      });
      const user = await userResp.json();
      const discordUserId = user.id;
      const discordUsername = user.global_name || user.username || user.id;

      // Fetch user's guilds to verify membership
      const guildsResp = await fetch('https://discord.com/api/v10/users/@me/guilds', {
        headers: { Authorization: 'Bearer ' + discordAccessToken },
      });
      const userGuilds = await guildsResp.json();
      let matchedGuildId = null;
      if (Array.isArray(allowedGuildIds) && allowedGuildIds.length > 0) {
        const userGuildIds = Array.isArray(userGuilds) ? userGuilds.map(g => String(g.id)) : [];
        matchedGuildId = allowedGuildIds.find(gid => userGuildIds.includes(String(gid))) || null;
      }
      if (!matchedGuildId) {
        pendingOAuth.set(state, { status: 'error', error: 'not_in_guild', timestamp: Date.now() });
        return res.send('<html><body style="background:#1a1a2e;color:#ff4a4a;font-family:sans-serif;text-align:center;padding:60px"><h2>Access Denied</h2><p>You are not a member of the required Discord server.</p><p style="color:#888">You can close this window.</p></body></html>');
      }

      // Hash the raw Discord ID | raw IDs are never stored in the database
      const hashedId = hashUserId(discordUserId);
      // Fetch/upsert guild member via bot for display name
      let displayName = discordUsername;
      if (dsgvo && typeof dsgvo.isBanned === 'function' && dsgvo.isBanned(hashedId)) {
        pendingOAuth.set(state, { status: 'error', error: 'banned', timestamp: Date.now() });
        return res.send('<html><body style="background:#1a1a2e;color:#ff4a4a;font-family:sans-serif;text-align:center;padding:60px"><h2>Access Denied</h2><p>Your account has been banned from this server.</p><p style="color:#888">You can close this window.</p></body></html>');
      }

      // Fetch guild member via bot to get the server nickname (not the Discord global username)
      if (_bot && typeof _bot.fetchGuildMember === 'function') {
        try {
          const member = await _bot.fetchGuildMember(String(discordUserId), String(matchedGuildId));
          if (member && member.displayName) {
            displayName = member.displayName;
          }
        } catch (e) {
          console.warn('[oauth] fetchGuildMember failed, using Discord username:', e.message);
        }
      }

      // Issue signed auth token (uid = hashed ID)
      const authPayload = {
        uid: hashedId,
        gid: matchedGuildId,
        name: displayName,
        iat: Date.now(),
        exp: Date.now() + 24 * 60 * 60 * 1000,
      };
      const authToken = signToken(authPayload, tokenSecret);

      // Store token in DB (hashed user ID) | remove old tokens for this user first
      db.prepare('DELETE FROM auth_tokens WHERE discord_user_id = ?').run(hashedId);
      db.prepare(
        'INSERT INTO auth_tokens (token_id, discord_user_id, guild_id, display_name, created_at_ms, expires_at_ms) VALUES (?,?,?,?,?,?)'
      ).run(authToken.substring(0, 64), hashedId, matchedGuildId, displayName, authPayload.iat, authPayload.exp);

      // Store result for companion app polling
      pendingOAuth.set(state, {
        status: 'success',
        token: authToken,
        displayName: displayName,
        policyVersion: policyVersion || '1.0',
        policyAccepted: dsgvo ? dsgvo.hasPolicyAcceptance(hashedId, policyVersion || '1.0') : true,
        timestamp: Date.now(),
      });
      // Revoke Discord access token (we don't need it anymore)
      try {
        await fetch('https://discord.com/api/v10/oauth2/token/revoke', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            token: discordAccessToken,
            token_type_hint: 'access_token',
            client_id: discordClientId,
          }),
        });
      } catch (e) { console.warn('[oauth] Token revoke failed:', e.message); }
      console.log('[oauth] Login OK: ' + hashedId.substring(0, 12) + '... (' + displayName + ') in guild ' + matchedGuildId);
      res.send('<html><body style="background:#1a1a2e;color:#4AFF9E;font-family:sans-serif;text-align:center;padding:60px"><h2>\u2713 Login Successful</h2><p>Logged in as <strong>' + displayName + '</strong></p><p style="color:#888">You can close this window and return to the companion app.</p></body></html>');
    } catch (e) {
      console.error('[oauth] Callback error:', e);
      pendingOAuth.set(state, { error: 'server_error', timestamp: Date.now() });
      res.status(500).send('<html><body style="background:#1a1a2e;color:#ff4a4a;font-family:sans-serif;text-align:center;padding:60px"><h2>Login Failed</h2><p>An unexpected error occurred.</p><p style="color:#888">You can close this window.</p></body></html>');
    }
  });

  // Step 3: Companion app polls this endpoint for the OAuth result
  app.get('/auth/discord/poll', authLimiter, (req, res) => {
    const { state } = req.query;
    if (!state) return res.status(400).json({ ok: false, error: 'missing state' });
    if (!pendingOAuth.has(state)) return res.json({ ok: true, data: { status: 'unknown' } });

    const result = pendingOAuth.get(state);
    if (result.status === 'pending') {
      return res.json({ ok: true, data: { status: 'pending' } });
    }
    if (result.status === 'error') {
      pendingOAuth.delete(state);
      return res.json({ ok: true, data: { status: 'error', error: result.error } });
    }

    // Success â return token and clean up
    pendingOAuth.delete(state);
    res.json({ ok: true, data: { status: 'success', token: result.token, displayName: result.displayName, policyVersion: result.policyVersion, policyAccepted: result.policyAccepted } });
  });

  app.get('/state/:discordUserId', (req, res) => {
    const hashedId = hashUserId(req.params.discordUserId);
    const row = stateStore.get(hashedId);
    res.json({ ok: true, data: row });
  });

  app.get('/state', (req, res) => {
    const token = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
    const tokenPayload = verifyToken(token, tokenSecret);
    if (!tokenPayload) return res.status(401).json({ ok: false, error: 'unauthorized' });
    const raw = parseInt(req.query.limit, 10);
    const limit = Math.min(Number.isFinite(raw) ? raw : 200, 1000);
    const rows = stateStore.listRecent(limit);
    res.json({ ok: true, data: rows });
  });

  // TX: create event
  app.post('/tx/event', (req, res) => {
    if (!txStore) return res.status(500).json({ ok: false, error: 'txStore_not_configured' });

    const { freqId, action, discordUserId, radioSlot, meta } = req.body || {};
    const f = Number(freqId);
    if (!Number.isInteger(f) || f < 1000 || f > 9999) {
      return res.status(400).json({ ok: false, error: 'bad freqId' });
    }
    if (action !== 'start' && action !== 'stop') {
      return res.status(400).json({ ok: false, error: 'bad action' });
    }
    const ts = Date.now();

    // Prefer user identity from signed Bearer token (already hashed)
    let hashedUid = null;
    const authHeader = req.headers['authorization'] || '';
    if (authHeader.startsWith('Bearer ')) {
      const tokenPayload = verifyToken(authHeader.slice(7), tokenSecret);
      if (tokenPayload && tokenPayload.uid) {
        hashedUid = tokenPayload.uid;
      }
    }
    // Fallback: hash raw Discord ID from body (legacy / admin-token callers)
    if (!hashedUid && discordUserId) {
      hashedUid = hashUserId(discordUserId);
    }
    const row = {
      freq_id: f,
      discord_user_id: hashedUid,
      radio_slot: (radioSlot === null || radioSlot === undefined) ? null : Number(radioSlot),
      action,
      ts_ms: ts,
      meta_json: meta ? JSON.stringify(meta) : null,
    };
    txStore.addEvent(row);
    const payload = {
      freqId: row.freq_id,
      discordUserId: hashedUid,
      radioSlot: row.radio_slot,
      action: row.action,
      ts: row.ts_ms,
      meta: meta || null,
    };
    const listenerCount = (db.prepare('SELECT COUNT(DISTINCT discord_user_id) as cnt FROM freq_listeners WHERE freq_id = ?').get(f) || {}).cnt || 0;

    // Broadcast TX event to WebSocket subscribers (voice relay + ws hub)
    if (typeof onTxEventFn === 'function') {
      onTxEventFn(payload);
    }

    res.json({ ok: true, data: payload, listener_count: listenerCount });
  });
  // TX: read
  app.get('/tx/recent', (req, res) => {
    const token = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
    const tokenPayload = verifyToken(token, tokenSecret);
    if (!tokenPayload) return res.status(401).json({ ok: false, error: 'unauthorized' });
    const raw = parseInt(req.query.limit, 10);
    const limit = Math.min(Number.isFinite(raw) ? raw : 200, 1000);
    const freq = req.query.freqId ? Number(req.query.freqId) : null;

    const rows = freq ? txStore.listRecentByFreq(freq, limit) : txStore.listRecent(limit);
    res.json({ ok: true, data: rows });
  });

  // Frequency listener registration
  app.post('/freq/join', (req, res) => {
    const token = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
    const tokenPayload = verifyToken(token, tokenSecret);
    if (!tokenPayload) return res.status(401).json({ ok: false, error: 'unauthorized' });
    const { freqId, radioSlot } = req.body || {};
    if (!freqId) {
      return res.status(400).json({ ok: false, error: 'missing freqId' });
    }
    const f = Number(freqId);
    if (!Number.isInteger(f) || f < 1000 || f > 9999) {
      return res.status(400).json({ ok: false, error: 'freqId must be 1000-9999' });
    }
    const hashedUid = tokenPayload.uid;
    db.prepare(
      'INSERT OR REPLACE INTO freq_listeners (discord_user_id, freq_id, radio_slot, connected_at_ms) VALUES (?,?,?,?)'
    ).run(hashedUid, f, Number(radioSlot) || 0, Date.now());
    const row = db.prepare('SELECT COUNT(DISTINCT discord_user_id) as cnt FROM freq_listeners WHERE freq_id = ?').get(f);
    res.json({ ok: true, listener_count: row ? row.cnt : 0 });
  });
  app.post('/freq/leave', (req, res) => {
    const token = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
    const tokenPayload = verifyToken(token, tokenSecret);
    if (!tokenPayload) return res.status(401).json({ ok: false, error: 'unauthorized' });
    const { freqId } = req.body || {};
    if (!freqId) {
      return res.status(400).json({ ok: false, error: 'missing freqId' });
    }
    const f = Number(freqId);
    if (!Number.isInteger(f) || f < 1000 || f > 9999) {
      return res.status(400).json({ ok: false, error: 'freqId must be 1000-9999' });
    }
    const hashedUid = tokenPayload.uid;
    db.prepare('DELETE FROM freq_listeners WHERE discord_user_id = ? AND freq_id = ?').run(hashedUid, f);
    const row = db.prepare('SELECT COUNT(DISTINCT discord_user_id) as cnt FROM freq_listeners WHERE freq_id = ?').get(f);
    res.json({ ok: true, listener_count: row ? row.cnt : 0 });
  });

  app.get('/users/recent', (req, res) => {
    const raw = parseInt(req.query.limit, 10);
    const limit = Math.min(Number.isFinite(raw) ? raw : 200, 1000);
    const rows = (usersStore && typeof usersStore.listRecent === 'function') ? usersStore.listRecent(limit) : [];
    res.json({ ok: true, data: rows || [] });
  });

  app.get('/users/:guildId/:discordUserId', (req, res) => {
    const { guildId, discordUserId } = req.params;
    const raw = parseInt(req.query.limit, 10);
    const limit = Math.min(Number.isFinite(raw) ? raw : 200, 1000);
    const hashedId = hashUserId(discordUserId);
    const row = (usersStore && typeof usersStore.get === 'function') ? usersStore.get(hashedId, guildId) : null;
    res.json({ ok: true, data: row });
  });
  app.post('/admin/reload', (req, res) => {
    const token = req.header('x-admin-token') || '';
    if (!adminToken || token !== adminToken) {
      return res.status(403).json({ ok: false, error: 'forbidden' });
    }
    mapping.reload();
    res.json({ ok: true, mappingSize: mapping.size() });
  });

  // --- DSGVO / Privacy compliance endpoints ---

  // Helper: admin auth check
  function requireAdmin(req, res) {
    const token = req.header('x-admin-token') || '';
    if (!adminToken || token !== adminToken) {
      res.status(403).json({ ok: false, error: 'forbidden' });
      return false;
    }
    return true;
  }

  // Get DSGVO status
  app.get('/admin/dsgvo/status', (req, res) => {
    if (!requireAdmin(req, res)) return;
    res.json({ ok: true, data: dsgvo.getStatus() });
  });

  // Enable/disable DSGVO compliance mode
  app.post('/admin/dsgvo/toggle', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const { enabled } = req.body || {};
    if (typeof enabled !== 'boolean') {
      return res.status(400).json({ ok: false, error: 'missing boolean "enabled"' });
    }
    dsgvo.setEnabled(enabled);
    res.json({ ok: true, data: dsgvo.getStatus() });
  });

  // Enable/disable debug mode
  app.post('/admin/dsgvo/debug', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const { enabled } = req.body || {};
    if (typeof enabled !== 'boolean') {
      return res.status(400).json({ ok: false, error: 'missing boolean "enabled"' });
    }
    dsgvo.setDebugMode(enabled);
    res.json({ ok: true, data: dsgvo.getStatus() });
  });

  // Delete all data for a specific user
  app.post('/admin/dsgvo/delete-user', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const { discordUserId } = req.body || {};
    if (!discordUserId) {
      return res.status(400).json({ ok: false, error: 'missing discordUserId' });
    }
    const hashedId = hashUserId(String(discordUserId));
    const result = dsgvo.deleteUser(hashedId);
    const kicked = _voiceRelay ? _voiceRelay.kickUser(hashedId) : 0;
    res.json({ ok: true, data: { ...result, kicked } });
  });

  // Delete all data for a specific guild
  app.post('/admin/dsgvo/delete-guild', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const { guildId } = req.body || {};
    if (!guildId) {
      return res.status(400).json({ ok: false, error: 'missing guildId' });
    }
    const result = dsgvo.deleteGuild(String(guildId));
    res.json({ ok: true, data: result });
  });

  // Manually trigger DSGVO cleanup
  app.post('/admin/dsgvo/cleanup', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const result = dsgvo.runCleanup();
    res.json({ ok: true, data: result });
  });

  // --- Channel sync endpoints ---
  app.post('/admin/channel-sync/interval', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const { hours } = req.body || {};
    if (!hours || typeof hours !== 'number' || hours < 1) {
      return res.status(400).json({ ok: false, error: 'missing or invalid "hours" (min 1)' });
    }
    _bot.setSyncInterval(hours);
    res.json({ ok: true, data: _bot.getSyncStatus() });
  });

  // Get frequency â channel name mappings (public, no auth required)
  app.get('/freq/names', (req, res) => {
    res.json({ ok: true, data: mapping.getFreqNames() });
  });

  // Get channel sync status
  app.get('/admin/channel-sync/status', (req, res) => {
    if (!requireAdmin(req, res)) return;
    if (!_bot || !_bot.getSyncStatus) {
      return res.status(500).json({ ok: false, error: 'bot not available' });
    }
    res.json({ ok: true, data: _bot.getSyncStatus() });
  });

  // Trigger manual channel sync
  app.post('/admin/channel-sync/trigger', async (req, res) => {
    if (!requireAdmin(req, res)) return;
    if (!_bot || !_bot.triggerChannelSync) {
      return res.status(500).json({ ok: false, error: 'bot not available' });
    }
    const result = await _bot.triggerChannelSync();
    res.json({ ok: true, data: result });
  });

  // --- Ban management endpoints ---
  app.post('/admin/ban', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const { discordUserId, reason } = req.body || {};
    if (!discordUserId) {
      return res.status(400).json({ ok: false, error: 'missing discordUserId' });
    }
    if (dsgvo && typeof dsgvo.banUser === 'function') {
      const hashedId = hashUserId(String(discordUserId));
      dsgvo.banUser(hashedId, String(discordUserId), reason || null);
      // Kick active voice sessions for this user
      const kicked = _voiceRelay ? _voiceRelay.kickUser(hashedId) : 0;
      console.log(`[admin] Unbanned user ${hashedId.substring(0, 12)}... removed=${removed}`);
      res.json({ ok: true, kicked });
    } else {
      res.status(500).json({ ok: false, error: 'dsgvo module not available' });
    }
  });
  app.post('/admin/unban', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const { discordUserId } = req.body || {};
    if (!discordUserId) {
      return res.status(400).json({ ok: false, error: 'missing discordUserId' });
    }
    if (dsgvo && typeof dsgvo.unbanUser === 'function') {
      const hashedId = hashUserId(String(discordUserId));
      const removed = dsgvo.unbanUser(hashedId);
      console.log(`[admin] Banned user ${hashedId.substring(0, 12)}... â ${kicked} session(s) kicked`);
      res.json({ ok: true, data: { removed } });
    } else {
      res.status(500).json({ ok: false, error: 'dsgvo module not available' });
    }
  });
  app.get('/admin/bans', (req, res) => {
    if (!requireAdmin(req, res)) return;
    if (dsgvo && typeof dsgvo.listBanned === 'function') {
      res.json({ ok: true, data: dsgvo.listBanned() });
    } else {
      res.json({ ok: true, data: [] });
    }
  });
  app.post('/admin/dsgvo/delete-and-ban', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const { discordUserId, reason } = req.body || {};
    if (!discordUserId) {
      return res.status(400).json({ ok: false, error: 'missing discordUserId' });
    }
    if (dsgvo && typeof dsgvo.deleteAndBanUser === 'function') {
      const hashedId = hashUserId(String(discordUserId));
      const result = dsgvo.deleteAndBanUser(hashedId, String(discordUserId), reason);
      // Kick active voice sessions for this user
      const kicked = _voiceRelay ? _voiceRelay.kickUser(hashedId) : 0;
      console.log(`[admin] Delete+Ban user ${hashedId.substring(0, 12)}... â ${kicked} session(s) kicked`);
      res.json({ ok: true, data: { ...result, kicked } });
    } else {
      res.status(500).json({ ok: false, error: 'dsgvo module not available' });
    }
  });
  // --- Log-Level Management ---
  const logger = require('./logger');
  app.get('/admin/log-level', (req, res) => {
    if (!requireAdmin(req, res)) return;
    res.json({ ok: true, data: logger.getStatus() });
  });

  app.post('/admin/log-level', (req, res) => {
    if (!requireAdmin(req, res)) return;
    const { service, level } = req.body || {};
    if (!level || !logger.VALID_LEVELS.includes(level)) {
      return res.status(400).json({ ok: false, error: 'invalid level (valid: ' + logger.VALID_LEVELS.join(', ') + ')' });
    }
    const target = service || 'all';
    try {
      logger.setLevel(target, level);
      res.json({ ok: true, data: logger.getStatus() });
      console.log(`[admin] Log-level set: ${target} â ${level}`);
    } catch (e) {
      res.status(400).json({ ok: false, error: e.message });
    }
  });
  const server = http.createServer(app);
  server._setOnTxEvent = (fn) => { onTxEventFn = fn; };
  server._setBot = (b) => { _bot = b; };
  server._setVoiceRelay = (vr) => { _voiceRelay = vr; };
  return server;
}

module.exports = { createHttpServer };