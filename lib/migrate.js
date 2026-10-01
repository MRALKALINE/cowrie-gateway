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

/* Partner withdrawals. Separate from the payouts table because a partner is not
   a merchant: there is no merchant_id to key on, and the two flows have
   different destinations, different approvers and different balances. Its own
   table also means a partner request can never be mistaken for a merchant's
   balance by the payout-availability query, which sums that table by
   merchant_id. */
CREATE TABLE IF NOT EXISTS partner_payouts (
  id          TEXT PRIMARY KEY,
  merchant_id TEXT NOT NULL,
  data        JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS partner_payouts_merchant_idx ON partner_payouts (merchant_id);

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

/* Support conversations. One row per message; a merchant's thread is every
   row carrying their merchant_id, ordered by time. Deliberately persistent
   rather than a live socket: an unanswered question has to survive a restart
   and sit in a queue an admin can work through. */
CREATE TABLE IF NOT EXISTS support_messages (
  id          TEXT PRIMARY KEY,
  merchant_id TEXT NOT NULL,
  data        JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS support_merchant_idx ON support_messages (merchant_id);

/* MCASH payment notifications. One row per IPN — previously an array in
   platform_settings, where concurrent writers (webhook, reconciler, admin
   apply) could clobber each other's read-modify-write and silently lose a
   payment record, killing its auto-confirmation. */
CREATE TABLE IF NOT EXISTS mcash_ipns (
  id   TEXT PRIMARY KEY,
  data JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS mcash_ipns_at_idx ON mcash_ipns (((data->>'at')::bigint) DESC);
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
CREATE INDEX IF NOT EXISTS partner_payouts_created_idx ON partner_payouts (((data->>'createdAt')::bigint) DESC);
CREATE INDEX IF NOT EXISTS events_created_idx   ON events   (((data->>'createdAt')::bigint) DESC);

/* Makes Idempotency-Key actually idempotent. Checking for an existing charge
   in application code leaves a window where two simultaneous requests both
   find nothing and both create one; the database has to enforce it. Partial,
   so the vast majority of charges (which carry no key) are unaffected. */
CREATE INDEX IF NOT EXISTS support_created_idx ON support_messages (((data->>'createdAt')::bigint));

CREATE UNIQUE INDEX IF NOT EXISTS charges_idempotency_idx
  ON charges (merchant_id, (data->>'idempotencyKey'), (COALESCE(data->>'mode','test')))
  WHERE data->>'idempotencyKey' IS NOT NULL;
`;

async function migrate() {
  await pool.query(SQL);
  await pool.query(ALTER);
  await pool.query(INDEXES);
  console.log('  ✓ Database tables ready');
}

module.exports = { migrate };
