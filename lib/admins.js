'use strict';
const crypto = require('crypto');
const store = require('./store');
const { hashPassword, verifyPassword } = require('./util');

/* Admin logins live in the `admins` table, hashed with scrypt and a
   per-password salt.

   They used to be a hardcoded list of plaintext passwords in this file. That
   list sat in a public repository, so those credentials must be treated as
   compromised — they are deliberately NOT migrated here. Anyone still using
   them has to be re-provisioned through seedAdmins() below. */

/* Constant-time comparison needs something to compare against when the email
   is unknown, otherwise a missing account returns faster than a wrong
   password and the response time reveals which emails are valid. */
const DUMMY_HASH = hashPassword(crypto.randomBytes(32).toString('hex'));

async function findAdmin(email, password) {
  const lc = String(email || '').trim().toLowerCase();
  const account = lc ? await store.admins.byEmail(lc) : null;
  const valid = verifyPassword(String(password || ''), account ? account.passwordHash : DUMMY_HASH);
  return account && valid ? { email: account.email, role: 'admin' } : null;
}

async function setPassword(email, password) {
  const lc = String(email || '').trim().toLowerCase();
  if (!lc) throw Object.assign(new Error('email is required.'), { status: 400 });
  if (String(password || '').length < 10) {
    throw Object.assign(new Error('Password must be at least 10 characters.'), { status: 400 });
  }
  const existing = await store.admins.byEmail(lc);
  return store.admins.upsert({
    email: lc,
    passwordHash: hashPassword(String(password)),
    createdAt: (existing && existing.createdAt) || Date.now(),
    updatedAt: Date.now(),
  });
}

async function listAdmins() {
  return (await store.admins.all()).map((a) => ({
    email: a.email, createdAt: a.createdAt, updatedAt: a.updatedAt,
  }));
}

async function removeAdmin(email) {
  const lc = String(email || '').trim().toLowerCase();
  if ((await store.admins.count()) <= 1) {
    throw Object.assign(new Error('Cannot remove the last admin account.'), { status: 400 });
  }
  await store.admins.del(lc);
}

/* Runs at boot. If ADMIN_EMAIL and ADMIN_PASSWORD are both set they define the
   admin account and its password is kept in sync. Otherwise, when no admins
   exist at all, one is created with a generated password printed once to the
   logs — so a fresh deployment is reachable without ever putting a password in
   source control. */
async function seedAdmins() {
  const email = (process.env.ADMIN_EMAIL || '').split(',')[0].trim().toLowerCase();
  const password = (process.env.ADMIN_PASSWORD || '').trim();
  const count = await store.admins.count();

  if (email && password) {
    await setPassword(email, password);
    if (!count) console.log(`  ✓ Admin account provisioned from ADMIN_EMAIL: ${email}`);
    return;
  }

  if (count) {
    if (!email || !password) {
      console.warn('  ⚠ ADMIN_EMAIL / ADMIN_PASSWORD are not set — existing admin accounts are unchanged.');
    }
    return;
  }

  const fallbackEmail = email || 'admin@cowrie.local';
  const generated = crypto.randomBytes(18).toString('base64url');
  await setPassword(fallbackEmail, generated);
  console.warn('\n  ================= ADMIN ACCOUNT CREATED =================');
  console.warn(`   email    : ${fallbackEmail}`);
  console.warn(`   password : ${generated}`);
  console.warn('   Shown once. Set ADMIN_EMAIL / ADMIN_PASSWORD in the');
  console.warn('   dashboard, or change it from the admin console.');
  console.warn('  =========================================================\n');
}

module.exports = { findAdmin, setPassword, listAdmins, removeAdmin, seedAdmins };
