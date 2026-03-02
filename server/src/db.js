'use strict';

const Database = require('better-sqlite3');

function initDb(dbPath) {
  const db = new Database(dbPath);

  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS voice_state (
      discord_user_id TEXT NOT NULL,
      guild_id        TEXT NOT NULL,
      channel_id      TEXT,
      freq_id         INTEGER,
      updated_at_ms   INTEGER NOT NULL,
      PRIMARY KEY (discord_user_id)
    );

    CREATE INDEX IF NOT EXISTS idx_voice_state_updated_at
      ON voice_state(updated_at_ms);

    CREATE TABLE IF NOT EXISTS tx_events (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      freq_id         INTEGER NOT NULL,
      discord_user_id TEXT,
      radio_slot      INTEGER,
      action          TEXT NOT NULL CHECK(action IN ('start','stop')),
      ts_ms           INTEGER NOT NULL,
      meta_json       TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_tx_events_ts
      ON tx_events(ts_ms);

    CREATE INDEX IF NOT EXISTS idx_tx_events_freq_ts
      ON tx_events(freq_id, ts_ms);

    -- User Directory (fÃ¼r "Server-Namen", nicht global_name)
    CREATE TABLE IF NOT EXISTS discord_users (
      discord_user_id TEXT NOT NULL,
      guild_id        TEXT NOT NULL,
      display_name    TEXT,
      updated_at_ms   INTEGER NOT NULL,
      PRIMARY KEY (discord_user_id, guild_id)
    );

    CREATE INDEX IF NOT EXISTS idx_discord_users_updated_at
      ON discord_users(updated_at_ms);

    CREATE INDEX IF NOT EXISTS idx_discord_users_guild_updated_at
      ON discord_users(guild_id, updated_at_ms);

    -- Frequency listener tracking (active radio users per freq)
    CREATE TABLE IF NOT EXISTS freq_listeners (
      discord_user_id TEXT NOT NULL,
      freq_id         INTEGER NOT NULL,
      radio_slot      INTEGER DEFAULT 0,
      connected_at_ms INTEGER NOT NULL,
      PRIMARY KEY (discord_user_id, freq_id)
    );

    CREATE INDEX IF NOT EXISTS idx_freq_listeners_freq
      ON freq_listeners(freq_id);

    -- Voice relay sessions
    CREATE TABLE IF NOT EXISTS voice_sessions (
      session_token   TEXT PRIMARY KEY,
      discord_user_id TEXT NOT NULL,
      guild_id        TEXT NOT NULL,
      display_name    TEXT,
      created_at_ms   INTEGER NOT NULL,
      last_seen_ms    INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_voice_sessions_user
      ON voice_sessions(discord_user_id);

    -- Banned users (minimal: user ID + timestamp + optional reason)
    CREATE TABLE IF NOT EXISTS banned_users (
      discord_user_id TEXT PRIMARY KEY,
      raw_discord_id  TEXT,
      banned_at_ms    INTEGER NOT NULL,
      reason          TEXT
    );

    -- Auth tokens (issued by POST /auth/login)
    CREATE TABLE IF NOT EXISTS auth_tokens (
      token_id        TEXT PRIMARY KEY,
      discord_user_id TEXT NOT NULL,
      guild_id        TEXT NOT NULL,
      display_name    TEXT,
      created_at_ms   INTEGER NOT NULL,
      expires_at_ms   INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_auth_tokens_user
      ON auth_tokens(discord_user_id);

    CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires
      ON auth_tokens(expires_at_ms);

    -- Privacy policy acceptance tracking
    CREATE TABLE IF NOT EXISTS policy_acceptance (
      discord_user_id TEXT NOT NULL,
      policy_version  TEXT NOT NULL,
      accepted_at_ms  INTEGER NOT NULL,
      PRIMARY KEY (discord_user_id, policy_version)
    );

    CREATE INDEX IF NOT EXISTS idx_policy_acceptance_user ON policy_acceptance(discord_user_id);
  `);

  return db;
}

module.exports = { initDb };