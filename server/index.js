'use strict';

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const { createHttpServer } = require('./src/http');
const { createWsHub } = require('./src/ws');
const { initDb } = require('./src/db');
const { createTxStore } = require('./src/tx');
const { createUsersStore } = require('./src/users');

const { createDiscordBot } = require('./src/discord');
const { createMappingStore } = require('./src/mapping');
const { createStateStore } = require('./src/state');
const { createVoiceRelay } = require('./src/voice');
const { createDsgvo } = require('./src/dsgvo');
const { hashUserId } = require('./src/crypto');
const logger = require('./src/logger');
const fs = require('fs');

function mustEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env var: ${name}`);
  return v;
}

/**
 * One-time migration: hash all existing raw Discord user IDs in every table.
 * Idempotent (immernoch ein geiles wort!) 
 */
function migrateUserIdHashing(db) {
  // 1. Ensure raw_discord_id column exists on banned_users (for fresh vs upgraded DBs)
  const cols = db.prepare('PRAGMA table_info(banned_users)').all();
  if (!cols.some(c => c.name === 'raw_discord_id')) {
    db.exec('ALTER TABLE banned_users ADD COLUMN raw_discord_id TEXT');
    console.log('[migration] Added raw_discord_id column to banned_users');
  }

  // 2. Check if migration is needed (heuristic: raw Discord snowflakes are 17-20 decimal digits)
  const tables = ['voice_state', 'tx_events', 'discord_users', 'freq_listeners', 'voice_sessions', 'auth_tokens', 'policy_acceptance'];
  let needsMigration = false;
  for (const table of tables) {
    const sample = db.prepare(`SELECT discord_user_id FROM ${table} WHERE discord_user_id IS NOT NULL LIMIT 1`).get();
    if (sample && !/^[0-9a-f]{64}$/.test(sample.discord_user_id)) {
      needsMigration = true;
      break;
    }
  }

  // Also check banned_users
  const bannedSample = db.prepare('SELECT discord_user_id FROM banned_users LIMIT 1').get();
  if (bannedSample && !/^[0-9a-f]{64}$/.test(bannedSample.discord_user_id)) {
    needsMigration = true;
  }

  if (!needsMigration) {
    console.log('[migration] User ID hashing: no migration needed');
    return;
  }

  console.log('[migration] Hashing existing raw discord_user_id values...');

  // 3. Migrate each standard table
  for (const table of tables) {
    const rows = db.prepare(`SELECT DISTINCT discord_user_id FROM ${table} WHERE discord_user_id IS NOT NULL`).all();
    let migrated = 0;
    const migrate = db.transaction(() => {
      for (const row of rows) {
        const raw = row.discord_user_id;
        if (/^[0-9a-f]{64}$/.test(raw)) continue; // already hashed
        const hashed = hashUserId(raw);
        db.prepare(`UPDATE ${table} SET discord_user_id = ? WHERE discord_user_id = ?`).run(hashed, raw);
        migrated++;
      }
    });
    migrate();
    if (migrated > 0) console.log(`[migration]   ${table}: hashed ${migrated} user IDs`);
  }

  // 4. Migrate banned_users (preserve raw ID for admin display)
  const bannedRows = db.prepare('SELECT discord_user_id, banned_at_ms, reason FROM banned_users').all();
  let bannedMigrated = 0;
  const migrateBanned = db.transaction(() => {
    for (const row of bannedRows) {
      const raw = row.discord_user_id;
      if (/^[0-9a-f]{64}$/.test(raw)) continue;
      const hashed = hashUserId(raw);
      db.prepare('UPDATE banned_users SET discord_user_id = ?, raw_discord_id = ? WHERE discord_user_id = ?').run(hashed, raw, raw);
      bannedMigrated++;
    }
  });
  migrateBanned();
  if (bannedMigrated > 0) console.log(`[migration]   banned_users: hashed ${bannedMigrated} entries (raw IDs preserved)`);

  console.log('[migration] User ID hashing migration complete');
}

(async () => {
  const bindHost = process.env.BIND_HOST || '127.0.0.1';
  const bindPort = Number(process.env.BIND_PORT || '3000');

  const dbPath = mustEnv('DB_PATH');
  const mapPath = mustEnv('CHANNEL_MAP_PATH');
  mustEnv('TOKEN_SECRET');

  const db = initDb(dbPath);

  // Run one-time user-ID hashing migration (idempotent)
  migrateUserIdHashing(db);

  const mapping = createMappingStore(mapPath);
  const stateStore = createStateStore(db);
  const txStore = createTxStore(db);
  const usersStore = createUsersStore(db);

  const tokenSecret = mustEnv('TOKEN_SECRET');

  // Discord OAuth2 config
  const discordClientId = process.env.DISCORD_CLIENT_ID || '';
  const discordClientSecret = process.env.DISCORD_CLIENT_SECRET || '';
  const discordRedirectUri = process.env.DISCORD_REDIRECT_URI || '';
  if (!discordClientId || !discordClientSecret || !discordRedirectUri) {
    console.warn('[WARN] Discord OAuth2 not fully configured (DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI)');
  }

  const policyVersion = process.env.POLICY_VERSION || '1.0';
  let policyText = 'No privacy policy configured.';
  const policyPath = process.env.POLICY_PATH || path.join(__dirname, '..', 'config', 'privacy-policy.md');
  try { policyText = fs.readFileSync(policyPath, 'utf-8'); } catch { console.warn('[WARN] Privacy policy file not found:', policyPath); }

  const dsgvo = createDsgvo({
    db,
    dsgvoEnabled: process.env.DSGVO_ENABLED === 'true',
    debugMode: process.env.DEBUG_MODE === 'true',
  });
  dsgvo.startScheduler();

  const httpServer = createHttpServer({
    db,
    mapping,
    stateStore,
    txStore,
    usersStore,
    dsgvo,
    bot: null, // set after bot creation
    adminToken: process.env.ADMIN_TOKEN || '',
    allowedGuildIds: process.env.DISCORD_GUILD_ID
      ? process.env.DISCORD_GUILD_ID.split(',')
      : [],
    tokenSecret,
    policyVersion,
    policyText,
    discordClientId,
    discordClientSecret,
    discordRedirectUri,
    appVersion: process.env.APP_VERSION || 'unknown',
  });

  const wsHub = createWsHub({ stateStore, tokenSecret });

  // Voice relay (WebSocket control + binary WS audio)
  const voiceRelay = createVoiceRelay({
    db,
    usersStore,
    allowedGuildIds: process.env.DISCORD_GUILD_ID
      ? process.env.DISCORD_GUILD_ID.split(',') 
      : [],
    tokenSecret,
    dsgvo,
  });
  voiceRelay.start();

  // Wire voice relay to HTTP server (for ban-kick functionality)
  if (typeof httpServer._setVoiceRelay === 'function') {
    httpServer._setVoiceRelay(voiceRelay);
  }

  // Pre-compute own domain origin for WebSocket origin checks (once at startup)
  let ownDomainOrigin = null;
  if (discordRedirectUri) {
    try { ownDomainOrigin = new URL(discordRedirectUri).origin; } catch { /* invalid redirect URI */ }
  }
  console.log('[http] WebSocket origin whitelist:', ownDomainOrigin || '(none, only origin-less connections allowed)');

  // Route WebSocket upgrades by path
  // DSGVO HTTPS enforcement: reject WS upgrades that didn't come through TLS (Traefik).
  // For upgrade requests, Express trust-proxy doesn't apply, so we check the raw header
  // but ONLY trust it when the connection comes from loopback (i.e. from Traefik).
  httpServer.on('upgrade', (req, socket, head) => {
    try {
      if (dsgvo && typeof dsgvo.getStatus === 'function') {
        const status = dsgvo.getStatus();
        if (status.dsgvoEnabled) {
          // Check if connection comes from loopback (Traefik)
          const remoteAddr = req.socket.remoteAddress || '';
          const isLoopback = remoteAddr === '127.0.0.1' || remoteAddr === '::1' || remoteAddr === '::ffff:127.0.0.1';
          // When from loopback (Traefik), trust X-Forwarded-Proto; otherwise assume plain http
          const proto = isLoopback
            ? (req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim()
            : 'http';
          if (proto !== 'https') {
            console.log('[http] DSGVO: rejected WS upgrade (not HTTPS), remote:', remoteAddr, 'proto:', proto);
            socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
            socket.destroy();
            return;
          }
        }
      }

      // WebSocket origin check: reject connections from browsers with unknown Origin
      // Allow if Origin matches our own domain (companion app on some .NET runtimes sends it)
      // Allow connections with no Origin header (desktop apps, curl, etc.)
      const wsOrigin = req.headers.origin || '';
      if (wsOrigin && wsOrigin !== 'null') {
        if (!ownDomainOrigin || wsOrigin !== ownDomainOrigin) {
          console.log('[http] Rejected WebSocket with browser Origin:', wsOrigin);
          socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
          socket.destroy();
          return;
        }
      }

      const pathname = new URL(req.url, 'http://localhost').pathname;
      console.log('[http] WS upgrade:', pathname, 'origin:', wsOrigin || '(none)');
      if (pathname === '/voice') {
        voiceRelay.handleUpgrade(req, socket, head);
      } else if (pathname === '/ws') {
        wsHub.handleUpgrade(req, socket, head);
      } else {
        socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
        socket.destroy();
      }
    } catch (err) {
      console.error('[http] WebSocket upgrade error:', err);
      try { socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n'); } catch { /* ignore */ }
      try { socket.destroy(); } catch { /* ignore */ }
    }
  });

  // Wire TX broadcast (keine circular deps)
  if (typeof httpServer._setOnTxEvent === 'function') {
    httpServer._setOnTxEvent((payload) => {
      wsHub.broadcast({ type: 'tx_event', payload });
      voiceRelay.notifyTxEvent(payload);
    });
  }

  // Discord voice_state broadcast bleibt wie gehabt
  const bot = createDiscordBot({
    token: mustEnv('DISCORD_TOKEN'),
    guildId: process.env.DISCORD_GUILD_ID || null,
    mapping,
    stateStore,
    usersStore,
    onStateChange: (payload) => wsHub.broadcast({ type: 'voice_state', payload }),
    channelSyncIntervalHours: Number(process.env.CHANNEL_SYNC_INTERVAL_HOURS || 24),
  });

  // Wire bot reference into httpServer for channel sync endpoints
  if (typeof httpServer._setBot === 'function') {
    httpServer._setBot(bot);
  }

  httpServer.listen(bindPort, bindHost, async () => {
    console.log(`[http] listening on http://${bindHost}:${bindPort}`);
    console.log(`[map] loaded ${mapping.size()} channel mappings from ${mapPath}`);
    await bot.start();
  });
})();