'use strict';
const pool = require('./db');

const SQL = `
CREATE TABLE IF NOT EXISTS merchants (
  id              TEXT PRIMARY KEY,
  email           TEXT UNIQUE NOT NULL,
  public_key      TEXT UNIQUE NOT NULL,
  secret_key      TEXT UNIQUE NOT NULL,
  live_public_key TEXT UNIQUE,
  live_secret_key TEXT UNIQUE,
  data            JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS charges (
  reference   TEXT PRIMARY KEY,
  merchant_id TEXT NOT NULL,
  data        JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS charges_merchant_idx ON charges (merchant_id);

CREATE TABLE IF NOT EXISTS events (
  id          TEXT PRIMARY KEY,
  merchant_id TEXT NOT NULL,
  data        JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS events_merchant_idx ON events (merchant_id);

CREATE TABLE IF NOT EXISTS payouts (
  id          TEXT PRIMARY KEY,
  merchant_id TEXT NOT NULL,
  data        JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS payouts_merchant_idx ON payouts (merchant_id);

CREATE TABLE IF NOT EXISTS settlements (
  id   TEXT PRIMARY KEY,
  data JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_verifications (
  email      TEXT PRIMARY KEY,
  otp        TEXT NOT NULL,
  data       JSONB NOT NULL,
  expires_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS platform_settings (
  key  TEXT PRIMARY KEY,
  data JSONB NOT NULL
);

/* Admin logins. Previously a hardcoded list of plaintext passwords in
   lib/admins.js, which sat in a public repository and remains in git history.
   Hashed with scrypt and a per-password salt, same as merchants. */
CREATE TABLE IF NOT EXISTS admins (
  email TEXT PRIMARY KEY,
  data  JSONB NOT NULL
);
`;

const ALTER = `
ALTER TABLE merchants ADD COLUMN IF NOT EXISTS live_public_key TEXT UNIQUE;
ALTER TABLE merchants ADD COLUMN IF NOT EXISTS live_secret_key TEXT UNIQUE;
`;

/* Every listing query sorts by ORDER BY (data->>'createdAt')::bigint DESC,
   which without a matching expression index means a full scan plus an
   in-memory sort on each call. The pool sets statement_timeout to 10s, so
   once the tables grow those queries start erroring — and the error handler
   forwards the raw message to whoever triggered it. The index expression has
   to match the query expression exactly, cast included, to be used. */
const INDEXES = `
CREATE INDEX IF NOT EXISTS charges_created_idx  ON charges  (((data->>'createdAt')::bigint) DESC);
CREATE INDEX IF NOT EXISTS charges_status_idx   ON charges  ((data->>'status'));
CREATE INDEX IF NOT EXISTS payouts_created_idx  ON payouts  (((data->>'createdAt')::bigint) DESC);
CREATE INDEX IF NOT EXISTS events_created_idx   ON events   (((data->>'createdAt')::bigint) DESC);
`;

async function migrate() {
  await pool.query(SQL);
  await pool.query(ALTER);
  await pool.query(INDEXES);
  console.log('  ✓ Database tables ready');
}

module.exports = { migrate };
