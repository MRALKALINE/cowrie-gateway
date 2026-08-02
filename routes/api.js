'use strict';
const express = require('express');
const store = require('../lib/store');
const cfg = require('../lib/config');
const payments = require('../lib/payments');
const nalopay = require('../lib/nalopay');
const webhooks = require('../lib/webhooks');
const { sendOtp, sendKycApproved, sendKycRejected, sendPendingTransferAlert, sendDepositAlert } = require('../lib/email');
const fx = require('../lib/fx');
const { toGhsMinor } = fx;
const {
  merchantId, apiKey, genId, hashPassword, verifyPassword, signToken, verifyToken,
} = require('../lib/util');
const { findAdmin, setPassword, listAdmins, removeAdmin } = require('../lib/admins');
const cloudinary = require('../lib/cloudinary');

const router = express.Router();

/* Returns all admin recipient emails as an array (supports comma-separated ADMIN_EMAIL) */
/* Alert recipients. Two lists had drifted apart: who can sign in (the `admins`
   table) and who gets notified (ADMIN_EMAIL). Adding an admin account did not
   subscribe them to anything, so a new admin silently received no alerts.
   Every admin account is now a recipient, with ADMIN_EMAIL still honoured for
   addresses that should be notified without having a login.

   Addresses are validated before use: one undeliverable recipient — the
   generated admin@…​.local fallback, say — can make the provider reject the
   whole message and take the real recipients down with it. */
const DELIVERABLE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

async function adminEmails() {
  const fromEnv = String(process.env.ADMIN_EMAIL || cfg.ADMIN_EMAIL || '').split(',');
  let fromAccounts = [];
  try {
    fromAccounts = (await store.admins.all()).map((a) => a.email);
  } catch (e) {
    console.warn(`[alerts] Could not read admin accounts: ${e.message}`);
  }
  return [...new Set([...fromEnv, ...fromAccounts].map((e) => String(e || '').trim().toLowerCase()))]
    .filter((e) => DELIVERABLE.test(e) && !e.endsWith('.local'));
}

/* ── rate limiters ── */
function rateLimit({ windowMs, max }) {
  const hits = new Map();
  // Prune expired entries every 5 min to prevent unbounded Map growth
  setInterval(() => {
    const now = Date.now();
    for (const [k, e] of hits) if (now > e.reset) hits.delete(k);
  }, 5 * 60_000).unref();

  return (req, res, next) => {
    const key = req.ip; const now = Date.now();
    const entry = hits.get(key) || { count: 0, reset: now + windowMs };
    if (now > entry.reset) { entry.count = 0; entry.reset = now + windowMs; }
    entry.count += 1; hits.set(key, entry);
    if (entry.count > max) {
      res.setHeader('Retry-After', Math.ceil((entry.reset - now) / 1000));
      const e = new Error('Too many requests, slow down.'); e.status = 429; return next(e);
    }
    next();
  };
}
const globalLimiter = rateLimit({ windowMs: 60_000, max: 200 }); // all routes
const authLimiter   = rateLimit({ windowMs: 60_000, max: 10  }); // login / register
const chargeLimiter = rateLimit({ windowMs: 60_000, max: 60  }); // charge creation
const payLimiter    = rateLimit({ windowMs: 60_000, max: 20  }); // payment actions

router.use(globalLimiter);

const ah = (fn) => (req, res, next) => fn(req, res, next).catch(next);

/* Hosted checkout link for a charge. Built from the forwarded proto/host so it
   is correct behind Render's proxy. */
function checkoutUrlFor(req, charge) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  return `${proto}://${req.get('host')}/checkout?reference=${encodeURIComponent(charge.reference)}`;
}

function publicMerchant(m) {
  const { passwordHash, ...rest } = m;
  return rest;
}

/* `new URL()` alone accepts javascript:, data:, file: and ftp:. These values
   are rendered as clickable links in the admin console, so the scheme must be
   restricted here — the dashboard's client-side check is bypassed by any
   merchant calling the API directly with their own token. */
function assertWebUrl(url, field = 'url') {
  let parsed;
  try { parsed = new URL(url); }
  catch { const e = new Error(`${field} must be a valid absolute URL.`); e.status = 400; throw e; }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    const e = new Error(`${field} must start with http:// or https://`); e.status = 400; throw e;
  }
  return parsed;
}

/* ── middleware ── */
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    const payload = token && verifyToken(token);
    const merchant = payload && await store.merchants.byId(payload.sub);
    if (!merchant) { const e = new Error('Unauthorized'); e.status = 401; return next(e); }
    if (merchant.locked) { const e = new Error('This account has been locked. Please contact support.'); e.status = 403; return next(e); }
    req.merchant = merchant;
    req.mode = (req.headers['x-cowrie-mode'] === 'live') ? 'live' : 'test';
    next();
  } catch (e) { next(e); }
}

async function resolveMerchantByKey(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const bearer = header.startsWith('Bearer ') ? header.slice(7) : null;
    const key = req.headers['x-public-key'] || (req.body && req.body.public_key) || bearer;
    if (!key) { const e = new Error('Invalid or missing API key'); e.status = 401; return next(e); }

    const isLive = key.includes('_live_');
    let merchant;
    if (isLive) {
      merchant = await store.merchants.byLivePublicKey(key) || await store.merchants.byLiveSecretKey(key);
    } else {
      merchant = await store.merchants.byPublicKey(key) || await store.merchants.bySecretKey(key);
    }
    if (!merchant) { const e = new Error('Invalid or missing API key'); e.status = 401; return next(e); }
    if (merchant.locked) { const e = new Error('This account has been locked.'); e.status = 403; return next(e); }
    req.merchant = merchant;
    req.mode = isLive ? 'live' : 'test';
    next();
  } catch (e) { next(e); }
}

async function loadCharge(req, res, next) {
  try {
    const charge = await store.charges.byReference(req.params.reference);
    if (!charge) { const e = new Error('Unknown charge reference.'); e.status = 404; return next(e); }
    req.charge = charge; next();
  } catch (e) { next(e); }
}

/* ====================== Auth (merchant) ====================== */

/* Step 1 — send OTP */
router.post('/auth/register', authLimiter, ah(async (req, res) => {
  const { businessName, email, password } = req.body || {};
  if (!businessName || !email || !password) {
    const e = new Error('businessName, email and password are required.'); e.status = 400; throw e;
  }
  if (String(password).length < 8) {
    const e = new Error('password must be at least 8 characters.'); e.status = 400; throw e;
  }
  if (await store.merchants.byEmail(email)) {
    const e = new Error('An account with this email already exists.'); e.status = 409; throw e;
  }

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Date.now() + 15 * 60 * 1000;

  await store.verifications.set(email, otp, {
    businessName,
    email,
    passwordHash: hashPassword(password),
    publicKey:      apiKey('public',  'test'),
    secretKey:      apiKey('secret',  'test'),
    livePublicKey:  apiKey('public',  'live'),
    liveSecretKey:  apiKey('secret',  'live'),
    webhookSecret: 'whsec_' + apiKey('secret', 'test').slice(16),
  }, expiresAt);

  await sendOtp(email, otp, businessName);

  res.status(202).json({
    status: 'verify_email',
    email,
    message: 'Check your email for a 6-digit verification code.',
  });
}));

/* Step 2 — verify OTP and create account */
router.post('/auth/verify-email', authLimiter, ah(async (req, res) => {
  const { email, otp } = req.body || {};
  if (!email || !otp) {
    const e = new Error('email and otp are required.'); e.status = 400; throw e;
  }

  const pending = await store.verifications.get(email);
  if (!pending) {
    const e = new Error('No pending verification for this email. Please register again.'); e.status = 404; throw e;
  }
  if (Date.now() > pending.expires_at) {
    await store.verifications.del(email);
    const e = new Error('Verification code expired. Please register again.'); e.status = 410; throw e;
  }
  if (pending.otp !== String(otp).replace(/\D/g, '')) {
    const e = new Error('Incorrect verification code.'); e.status = 400; throw e;
  }
  if (await store.merchants.byEmail(email)) {
    await store.verifications.del(email);
    const e = new Error('An account with this email already exists.'); e.status = 409; throw e;
  }

  const pd = pending.data;
  const merchant = await store.merchants.insert({
    id: merchantId(),
    businessName: pd.businessName,
    email: pd.email,
    passwordHash: pd.passwordHash,
    publicKey:     pd.publicKey,
    secretKey:     pd.secretKey,
    livePublicKey: pd.livePublicKey,
    liveSecretKey: pd.liveSecretKey,
    webhookSecret: pd.webhookSecret,
    webhookUrl: null,
    demo: false,
    createdAt: Date.now(),
  });
  await store.verifications.del(email);

  const token = signToken({ sub: merchant.id, exp: Date.now() + cfg.TOKEN_TTL_MS });
  res.status(201).json({ token, merchant: publicMerchant(merchant) });
}));

/* Resend OTP */
router.post('/auth/resend-otp', authLimiter, ah(async (req, res) => {
  const { email } = req.body || {};
  if (!email) { const e = new Error('email is required.'); e.status = 400; throw e; }

  const pending = await store.verifications.get(email);
  if (!pending) { const e = new Error('No pending verification found. Please register again.'); e.status = 404; throw e; }

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Date.now() + 15 * 60 * 1000;
  await store.verifications.set(email, otp, pending.data, expiresAt);
  await sendOtp(email, otp, pending.data.businessName);

  res.json({ status: 'verify_email', email, message: 'A new code has been sent to your email.' });
}));

/* Forgot password — step 1: request reset code */
router.post('/auth/forgot-password', authLimiter, ah(async (req, res) => {
  const lc = String(req.body?.email || '').trim().toLowerCase();
  if (!lc || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(lc)) {
    const e = new Error('Enter a valid email address.'); e.status = 400; throw e;
  }
  const merchant = await store.merchants.byEmail(lc);
  if (merchant) {
    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const key = '__reset__' + lc;
    await store.verifications.set(key, otp, { type: 'reset', email: lc }, Date.now() + 15 * 60 * 1000);
    /* A send failure must not change the response. Awaiting this unguarded
       meant an email outage (a provider quota, say) turned a known address
       into a 500 while an unknown one still returned 200 — which tells an
       attacker exactly which addresses have accounts, defeating the identical
       message below. The code is already stored, so a retry once mail is
       working will deliver it. */
    try {
      await sendOtp(lc, otp, merchant.businessName);
    } catch (err) {
      console.error(`[reset] Could not send reset code to ${lc}: ${err.message}`);
    }
  }
  // Always respond the same way to prevent email enumeration
  res.json({ message: 'If an account exists for that email, a reset code has been sent.' });
}));

/* Forgot password — step 1b: verify OTP only (no password change yet) */
router.post('/auth/verify-reset-otp', authLimiter, ah(async (req, res) => {
  const { email, otp } = req.body || {};
  const lc = String(email || '').trim().toLowerCase();
  if (!lc || !otp) { const e = new Error('email and otp are required.'); e.status = 400; throw e; }
  const key = '__reset__' + lc;
  const pending = await store.verifications.get(key);
  if (!pending || pending.otp !== String(otp).trim() || Date.now() > Number(pending.expires_at)) {
    const e = new Error('Invalid or expired reset code.'); e.status = 400; throw e;
  }
  res.json({ ok: true });
}));

/* Forgot password — step 2: verify code + set new password */
router.post('/auth/reset-password', authLimiter, ah(async (req, res) => {
  const { email, otp, password } = req.body || {};
  const lc = String(email || '').trim().toLowerCase();
  if (!lc || !otp || !password) {
    const e = new Error('email, otp and password are required.'); e.status = 400; throw e;
  }
  if (String(password).length < 8) {
    const e = new Error('Password must be at least 8 characters.'); e.status = 400; throw e;
  }
  const key = '__reset__' + lc;
  const pending = await store.verifications.get(key);
  if (!pending || pending.otp !== String(otp).trim() || Date.now() > Number(pending.expires_at)) {
    const e = new Error('Invalid or expired reset code.'); e.status = 400; throw e;
  }
  const merchant = await store.merchants.byEmail(lc);
  if (!merchant) { const e = new Error('Account not found.'); e.status = 404; throw e; }
  merchant.passwordHash = hashPassword(password);
  await store.merchants.update(merchant);
  await store.verifications.del(key);
  res.json({ message: 'Password updated. Please sign in.' });
}));

/* Login */
router.post('/auth/login', authLimiter, ah(async (req, res) => {
  const { email, password, remember } = req.body || {};
  const merchant = email && await store.merchants.byEmail(email);
  if (!merchant || !verifyPassword(password || '', merchant.passwordHash)) {
    const e = new Error('Invalid email or password.'); e.status = 401; throw e;
  }
  if (merchant.locked) {
    const e = new Error('This account has been locked. Please contact support.'); e.status = 403; throw e;
  }
  const ttl = remember ? cfg.REMEMBER_TTL_MS : cfg.TOKEN_TTL_MS;
  const token = signToken({ sub: merchant.id, exp: Date.now() + ttl });
  res.json({ token, merchant: publicMerchant(merchant) });
}));

router.get('/me', requireAuth, (req, res) => {
  res.json({ merchant: publicMerchant(req.merchant) });
});

/* Public config — tells the checkout whether a gateway is wired up.
   Nalopay publishes no test/live key prefixes, so "not configured" is the
   only signal we can derive; NALOPAY_TEST_MODE lets you force the banner on. */
router.get('/info', (req, res) => {
  res.json({ testMode: !nalopay.configured() || process.env.NALOPAY_TEST_MODE === 'true' });
});

router.put('/me/webhook', requireAuth, ah(async (req, res) => {
  const { url } = req.body || {};
  if (url) assertWebUrl(url, 'webhook url');
  req.merchant.webhookUrl = url || null;
  await store.merchants.update(req.merchant);
  res.json({ merchant: publicMerchant(req.merchant) });
}));

router.put('/me/website', requireAuth, ah(async (req, res) => {
  const { url } = req.body || {};
  if (url) assertWebUrl(url, 'website url');
  req.merchant.websiteUrl = url || null;
  await store.merchants.update(req.merchant);
  res.json({ merchant: publicMerchant(req.merchant) });
}));

router.get('/transactions', requireAuth, ah(async (req, res) => {
  const all = await store.charges.forMerchant(req.merchant.id);
  const mode = req.mode || 'test';
  const raw = all.filter(c => (c.mode || 'test') === mode);
  const rates = await fx.getRates();
  const transactions = raw.map(c => ({ ...c, amountGhs: fx.toGhsMinor(c.amount, c.currency, rates) }));
  res.json({ transactions });
}));

router.delete('/transactions', requireAuth, ah(async (req, res) => {
  const { mode } = req.query;
  if (mode === 'live' || mode === 'test') {
    await store.charges.clearForMerchantByMode(req.merchant.id, mode);
  } else {
    await store.charges.clearForMerchant(req.merchant.id);
  }
  res.json({ ok: true });
}));

router.get('/events', requireAuth, ah(async (req, res) => {
  res.json({ events: await store.events.forMerchant(req.merchant.id) });
}));

/* ========================= Payment Links ========================= */

router.get('/payment-links', requireAuth, ah(async (req, res) => {
  const all = await store.charges.forMerchant(req.merchant.id);
  const mode = req.mode || 'test';
  const links = all.filter((c) => c.paymentLink && (c.mode || 'test') === mode);
  res.json({ links });
}));

router.post('/payment-links', requireAuth, chargeLimiter, ah(async (req, res) => {
  const { amount, currency, email, description, openAmount } = req.body || {};
  const isOpen = Boolean(openAmount);
  const amountMinor = isOpen ? 0 : Math.round(Number(amount) * 100);
  if (!isOpen && (!amountMinor || amountMinor < 100)) {
    const e = new Error('Enter a valid amount (minimum 1).'); e.status = 400; throw e;
  }
  const charge = await payments.createCharge(req.merchant, {
    amount: amountMinor,
    currency: String(currency || 'GHS').toUpperCase(),
    email: String(email || '').trim() || null,
    metadata: { description: String(description || '').trim() },
    openAmount: isOpen,
  });
  charge.mode = req.mode || 'test';
  charge.paymentLink = true;
  await store.charges.update(charge);
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  const checkoutUrl = `${proto}://${req.get('host')}/checkout?reference=${charge.reference}`;
  res.status(201).json({ charge, checkoutUrl });
}));

router.post('/charges/:reference/set-amount', payLimiter, loadCharge, ah(async (req, res) => {
  const charge = req.charge;
  if (!charge.openAmount) { const e = new Error('This charge has a fixed amount.'); e.status = 400; throw e; }
  if (charge.status !== 'pending') { const e = new Error('Charge is no longer pending.'); e.status = 409; throw e; }

  /* NOTE: this endpoint takes MAJOR units (what the shopper types, e.g. 50 for
     GHS 50) while POST /charges takes MINOR units. Different callers, kept
     deliberately — the checkout form posts what was typed.

     Number('Infinity') and Number('1e400') both survive the old
     `!amount || amount < 100` check, and JSON.stringify then writes Infinity
     out as null, leaving a charge with a null amount. Validate the input
     before scaling it, not after. */
  const major = Number(req.body.amount);
  if (!Number.isFinite(major) || major < 1 || major > MAX_AMOUNT_MAJOR) {
    const e = new Error(`Enter a valid amount between 1 and ${MAX_AMOUNT_MAJOR.toLocaleString()}.`);
    e.status = 400; throw e;
  }
  charge.amount = Math.round(major * 100);
  charge.updatedAt = Date.now();
  charge.openAmount = false;
  await store.charges.update(charge);
  res.json({ charge });
}));

/* ========================= Charges ========================= */

router.post('/charges', chargeLimiter, resolveMerchantByKey, ah(async (req, res) => {
  const mode = req.mode || 'test';
  const idemKey = req.headers['idempotency-key'] || null;

  /* Fast path: a repeat of a request we have already answered. */
  if (idemKey) {
    const existing = await store.charges.byIdempotencyKey(req.merchant.id, idemKey, mode);
    if (existing) return res.status(200).json({ charge: existing, checkout_url: checkoutUrlFor(req, existing) });
  }

  let charge;
  try {
    charge = await payments.createCharge(req.merchant, { ...(req.body || {}), mode, idempotencyKey: idemKey });
  } catch (err) {
    /* A concurrent request with the same key won the insert. The unique index
       is what actually guarantees idempotency — the check above only saves a
       round trip. 23505 is unique_violation. */
    if (idemKey && err.code === '23505') {
      const existing = await store.charges.byIdempotencyKey(req.merchant.id, idemKey, mode);
      if (existing) return res.status(200).json({ charge: existing, checkout_url: checkoutUrlFor(req, existing) });
    }
    throw err;
  }
  res.status(201).json({ charge, checkout_url: checkoutUrlFor(req, charge) });
}));

router.get('/charges/:reference', loadCharge, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.charge.merchantId);
  res.json({ charge: {
    ...req.charge,
    merchantName:    merchant ? merchant.businessName : 'KassifyPay',
    merchantWebsite: merchant ? (merchant.websiteUrl || null) : null,
  }});
}));

/* REMOVED — /method, /authorize and /confirm were survivors of the original
   simulated demo gateway and were never taken out when real money started
   flowing. All three were unauthenticated and settled a charge without any
   payment: /method moved a charge into an "awaiting" state, then /confirm
   marked it paid outright and /authorize accepted any six digits. Anyone
   holding a checkout link could mark their own order paid and trigger the
   merchant's charge.success webhook. Settlement now happens only in
   confirmWithNalopay(), against Nalopay's own record of the payment. */


/* Removed: this handed a working payment key to any unauthenticated caller.
   Integrations picked it up instead of their own key, so their payments were
   collected against the hidden demo account and never appeared in their
   dashboard. Merchants take their keys from /dashboard. */

/* ========================= Admin ========================= */

function requireAdminAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token && verifyToken(token);
  if (!payload || payload.role !== 'admin') {
    const e = new Error('Admin access required.'); e.status = 401; return next(e);
  }
  req.adminEmail = payload.email || null;
  next();
}

router.post('/admin/auth/login', authLimiter, ah(async (req, res) => {
  const { email, password } = req.body || {};
  const account = await findAdmin(email, password);
  if (!account) {
    const e = new Error('Invalid admin credentials.'); e.status = 401; throw e;
  }
  const token = signToken({ sub: 'admin', email: account.email, role: 'admin', exp: Date.now() + cfg.TOKEN_TTL_MS });
  res.json({ token, admin: { email: account.email, role: 'admin' } });
}));

/* Admin account management — lets the compromised credentials that used to be
   hardcoded actually be rotated, rather than only removed from source. */
router.get('/admin/admins', requireAdminAuth, ah(async (req, res) => {
  res.json({ admins: await listAdmins() });
}));

router.put('/admin/password', requireAdminAuth, ah(async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!(await findAdmin(req.adminEmail, currentPassword))) {
    const e = new Error('Current password is incorrect.'); e.status = 401; throw e;
  }
  await setPassword(req.adminEmail, newPassword);
  res.json({ ok: true });
}));

router.post('/admin/admins', requireAdminAuth, ah(async (req, res) => {
  const { email, password } = req.body || {};
  await setPassword(email, password);
  res.status(201).json({ ok: true, email: String(email).trim().toLowerCase() });
}));

router.delete('/admin/admins/:email', requireAdminAuth, ah(async (req, res) => {
  const target = String(req.params.email || '').trim().toLowerCase();
  if (target === String(req.adminEmail || '').toLowerCase()) {
    const e = new Error('You cannot remove your own account.'); e.status = 400; throw e;
  }
  await removeAdmin(target);
  res.json({ ok: true });
}));

router.get('/admin/auth/me', requireAdminAuth, (req, res) => {
  res.json({ admin: { email: req.adminEmail, role: 'admin' } });
});

router.get('/admin/overview', requireAdminAuth, ah(async (req, res) => {
  const allCharges = await store.charges.all();
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const todayTs = today.getTime();

  const rates = await fx.getRates();
  const toGhs = (amount, currency) => fx.toGhsMinor(amount, currency, rates);

  const successAll = allCharges.filter((c) => c.status === 'success');
  const liveSuccess = successAll.filter((c) => (c.mode || 'test') === 'live');
  const testSuccess = successAll.filter((c) => (c.mode || 'test') === 'test');
  const allPayouts = await store.payouts.all();
  /* Dated by paidAt — when the money actually arrived — not createdAt. A
     charge raised late yesterday and approved this morning is today's revenue,
     and one raised today but never paid is nobody's. Falls back to createdAt
     for records predating that field. */
  const paidTodayList = liveSuccess.filter((c) => (c.paidAt || c.createdAt) >= todayTs);
  const collectedToday = paidTodayList.reduce((s, c) => s + toGhs(c.amount, c.currency), 0);
  const collectedTodayCount = paidTodayList.length;
  const grossCollected = liveSuccess.reduce((s, c) => s + toGhs(c.amount, c.currency), 0);
  const testCollected  = testSuccess.reduce((s, c) => s + toGhs(c.amount, c.currency), 0);
  const totalPaidOut   = allPayouts.filter((p) => p.status === 'completed').reduce((s, p) => s + p.amount, 0);
  const totalCollected = Math.max(0, grossCollected - totalPaidOut);
  const paidOutToday = allPayouts.filter((p) => p.createdAt >= todayTs && p.status === 'completed').reduce((s, p) => s + p.amount, 0);
  const total = allCharges.length;
  const successRate = total > 0 ? ((successAll.length / total) * 100).toFixed(1) : '100.0';
  const pendingCount = allCharges.filter((c) => !['success', 'failed'].includes(c.status)).length;
  const allMerchants = await store.merchants.all();
  const merchantCount = allMerchants.filter((m) => !m.demo).length;

  const last7Days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - i);
    const start = d.getTime(); const end = start + 86_400_000;
    const daySucc = successAll.filter((c) => c.createdAt >= start && c.createdAt < end);
    last7Days.push({ date: d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }), amount: daySucc.reduce((s, c) => s + toGhs(c.amount, c.currency), 0), count: daySucc.length });
  }

  const byMethod = {};
  successAll.forEach((c) => { const m = c.method || 'unknown'; byMethod[m] = (byMethod[m] || 0) + toGhs(c.amount, c.currency); });

  res.json({ overview: { collectedToday, collectedTodayCount, paidOutToday, totalCollected, testCollected, merchantCount, successRate, pendingCount, last7Days, byMethod } });
}));

router.get('/admin/members', requireAdminAuth, ah(async (req, res) => {
  /* Demo accounts used to be hidden here. They still take real payments, so
     hiding them meant money could be collected against an account that never
     appeared in the console — flag them instead of filtering them out. */
  const merchants = await store.merchants.all();
  const [allCharges, allPayouts] = await Promise.all([store.charges.all(), store.payouts.all()]);
  const rates = await fx.getRates();
  const toGhs = (amount, currency) => fx.toGhsMinor(amount, currency, rates);
  const members = merchants.map((m) => {
    const charges = allCharges.filter((c) => c.merchantId === m.id);
    const successful = charges.filter((c) => c.status === 'success');
    const liveOk = successful.filter((c) => (c.mode || 'test') === 'live');
    const testOk = successful.filter((c) => (c.mode || 'test') === 'test');
    const livePaidOut = allPayouts
      .filter((p) => p.merchantId === m.id && p.status === 'completed' && (p.mode || 'test') === 'live')
      .reduce((s, p) => s + p.amount, 0);
    const testPaidOut = allPayouts
      .filter((p) => p.merchantId === m.id && p.status === 'completed' && (p.mode || 'test') === 'test')
      .reduce((s, p) => s + p.amount, 0);
    return {
      id: m.id,
      businessName: m.businessName,
      email: m.email,
      websiteUrl: m.websiteUrl || null,
      createdAt: m.createdAt,
      locked: !!m.locked,
      demo: !!m.demo,
      liveCollected: Math.max(0, liveOk.reduce((s, c) => s + toGhs(c.amount, c.currency), 0) - livePaidOut),
      testCollected: Math.max(0, testOk.reduce((s, c) => s + toGhs(c.amount, c.currency), 0) - testPaidOut),
      totalTransactions: charges.length,
      liveTransactions: charges.filter((c) => (c.mode || 'test') === 'live').length,
      successfulTransactions: successful.length,
    };
  });
  res.json({ members });
}));

router.get('/admin/members/:merchantId/transactions', requireAdminAuth, ah(async (req, res) => {
  const charges = await store.charges.forMerchant(req.params.merchantId);
  charges.sort((a, b) => b.createdAt - a.createdAt);
  res.json({ transactions: charges });
}));

router.post('/admin/members/:merchantId/lock', requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  if (!merchant) { const e = new Error('Merchant not found.'); e.status = 404; throw e; }
  merchant.locked = !!(req.body && req.body.locked);
  await store.merchants.update(merchant);
  res.json({ ok: true, merchantId: merchant.id, locked: merchant.locked });
}));

router.delete('/admin/transactions', requireAdminAuth, ah(async (req, res) => {
  const { mode } = req.query; // ?mode=live or ?mode=test — omit for all
  if (mode === 'live' || mode === 'test') {
    await store.charges.clearByMode(mode);
  } else {
    await store.charges.clearAll();
  }
  res.json({ ok: true });
}));



router.get('/admin/transactions', requireAdminAuth, ah(async (req, res) => {
  const all = await store.merchants.all();
  const merchantMap = {};
  all.forEach((m) => { merchantMap[m.id] = m.businessName; });
  const transactions = (await store.charges.all())
    .map((c) => ({ ...c, merchantName: merchantMap[c.merchantId] || 'Unknown' }));
  res.json({ transactions });
}));

router.get('/admin/payouts', requireAdminAuth, ah(async (req, res) => {
  const all = await store.merchants.all();
  const merchantMap = {};
  all.forEach((m) => { merchantMap[m.id] = m.businessName; });
  const payouts = (await store.payouts.all())
    .map((p) => ({ ...p, merchantName: merchantMap[p.merchantId] || 'Unknown' }));
  res.json({ payouts });
}));

router.post('/admin/payouts', requireAdminAuth, ah(async (req, res) => {
  const { amount, currency, recipient, method, note } = req.body || {};
  if (!amount || Number(amount) <= 0) { const e = new Error('amount must be a positive number in minor units.'); e.status = 400; throw e; }
  if (!recipient || !String(recipient).trim()) { const e = new Error('recipient is required.'); e.status = 400; throw e; }
  const all = await store.merchants.all();
  const merchant = all.find((m) => m.demo) || all[0];
  if (!merchant) { const e = new Error('No merchant available.'); e.status = 400; throw e; }
  const payout = await store.payouts.insert({
    id: genId('pyt_'), merchantId: merchant.id, amount: Math.round(Number(amount)),
    currency: currency || 'GHS', recipient: String(recipient).trim(),
    method: method || 'bank_transfer', note: String(note || '').trim(),
    status: 'processing', createdAt: Date.now(),
  });
  res.status(201).json({ payout });
}));

router.post('/admin/payouts/:id/complete', requireAdminAuth, ah(async (req, res) => {
  const payout = await store.payouts.byId(req.params.id);
  if (!payout) { const e = new Error('Payout not found.'); e.status = 404; throw e; }
  if (payout.status === 'completed') { const e = new Error('Payout already completed.'); e.status = 409; throw e; }
  payout.status = 'completed'; payout.completedAt = Date.now();
  await store.payouts.update(payout);
  res.json({ payout });
}));

/* ── merchant payout requests ── */
router.get('/payouts', requireAuth, ah(async (req, res) => {
  const all = await store.payouts.forMerchant(req.merchant.id);
  const mode = req.mode || 'test';
  res.json({ payouts: all.filter(p => (p.mode || 'test') === mode) });
}));

router.post('/payouts', requireAuth, ah(async (req, res) => {
  const { amount, method, bank, accountNumber, accountName, mobileProvider, mobileNumber, note } = req.body || {};
  const amt = Math.round(Number(amount));
  if (!amt || amt <= 0) { const e = new Error('Enter a valid amount.'); e.status = 400; throw e; }
  if (method === 'bank' && (!String(accountNumber || '').trim() || !String(accountName || '').trim())) {
    const e = new Error('Account number and account name are required for bank payouts.'); e.status = 400; throw e;
  }
  if (method === 'mobile_money' && !String(mobileNumber || '').trim()) {
    const e = new Error('Mobile money number is required.'); e.status = 400; throw e;
  }
  const payout = await store.payouts.insert({
    id: genId('pyt_'), merchantId: req.merchant.id,
    amount: amt, currency: 'GHS',
    mode: req.mode || 'test',
    method: method || 'bank',
    bank: String(bank || '').trim(),
    accountNumber: String(accountNumber || '').trim(),
    accountName: String(accountName || '').trim(),
    mobileProvider: String(mobileProvider || '').trim(),
    mobileNumber: String(mobileNumber || '').trim(),
    note: String(note || '').trim(),
    status: 'pending', createdAt: Date.now(),
  });
  res.status(201).json({ payout });
}));

router.get('/admin/settlements', requireAdminAuth, ah(async (req, res) => {
  res.json({ settlements: await store.settlements.all() });
}));

router.post('/admin/settlements', requireAdminAuth, ah(async (req, res) => {
  const unsettled = (await store.charges.all()).filter((c) => c.status === 'success' && !c.settled);
  if (!unsettled.length) { const e = new Error('No unsettled successful transactions to settle.'); e.status = 400; throw e; }
  const amount = unsettled.reduce((s, c) => s + c.amount, 0);
  /* Admin bulk settlement — marks a flag on already-terminal charges, so the
     version check would only add spurious conflicts. */
  await Promise.all(unsettled.map((c) => { c.settled = true; return store.charges.forceUpdate(c); }));
  const settlement = await store.settlements.insert({
    id: genId('stl_'), merchantId: 'admin', amount, currency: 'GHS',
    chargeCount: unsettled.length, status: 'completed', createdAt: Date.now(),
  });
  res.status(201).json({ settlement });
}));

router.post('/admin/new-payment', requireAdminAuth, ah(async (req, res) => {
  const { amount, currency, email, mode, openAmount } = req.body || {};
  const isOpen = Boolean(openAmount);
  const all = await store.merchants.all();
  const merchant = all.find((m) => m.demo) || all[0];
  if (!merchant) { const e = new Error('No merchant available.'); e.status = 400; throw e; }
  const charge = await payments.createCharge(merchant, {
    amount: isOpen ? 0 : Number(amount) || 0,
    currency: currency || 'GHS',
    email: String(email || '').trim(),
    openAmount: isOpen,
  });
  charge.mode = (mode === 'live') ? 'live' : 'test';
  await store.charges.update(charge);
  res.status(201).json({ charge, checkoutUrl: `/checkout?reference=${charge.reference}` });
}));

/* ========================= Bank accounts (manual transfer) ========================= */

const NG_BANKS = [
  'Access Bank','Citibank Nigeria','Ecobank Nigeria','Fidelity Bank','First Bank of Nigeria',
  'First City Monument Bank','Globus Bank','Guaranty Trust Bank','Heritage Bank','Keystone Bank',
  'Kuda Bank','Moniepoint Microfinance Bank','OPay','Paga','Palmpay','Polaris Bank','Providus Bank',
  'Stanbic IBTC Bank','Standard Chartered Bank','Sterling Bank','Suntrust Bank','Union Bank',
  'United Bank for Africa','Unity Bank','VFD Microfinance Bank','Wema Bank','Zenith Bank',
];

router.get('/admin/bank-accounts', requireAdminAuth, ah(async (req, res) => {
  const accounts = (await store.settings.get('bank_accounts')) || [];
  res.json({ accounts, banks: NG_BANKS });
}));

router.put('/admin/bank-accounts', requireAdminAuth, ah(async (req, res) => {
  const { accounts } = req.body || {};
  if (!Array.isArray(accounts)) throw Object.assign(new Error('accounts must be an array.'), { status: 400 });
  const cleaned = accounts.slice(0, 5).map(a => ({
    id: a.id || genId('bac_'),
    bankName:      String(a.bankName      || '').trim(),
    accountNumber: String(a.accountNumber || '').trim(),
    accountName:   String(a.accountName   || '').trim(),
    currency:      String(a.currency      || 'NGN').toUpperCase(),
    active:        a.active !== false,
  })).filter(a => a.bankName && a.accountNumber && a.accountName);
  await store.settings.set('bank_accounts', cleaned);
  res.json({ accounts: cleaned });
}));

router.get('/bank-accounts', ah(async (req, res) => {
  const all = (await store.settings.get('bank_accounts')) || [];
  const { currency } = req.query;
  const accounts = all.filter(a => a.active !== false && (!currency || a.currency === currency));
  res.json({ accounts });
}));

/* Called by checkout when customer views static bank details — emails admin once per charge */
router.post('/charges/:reference/notify-transfer', loadCharge, ah(async (req, res) => {
  const charge = req.charge;
  const { payerName } = req.body || {};
  if (payerName && String(payerName).trim() && !charge.payerName) charge.payerName = String(payerName).trim();
  if (charge.transferNotified) { await store.charges.update(charge); return res.json({ ok: true }); }
  charge.transferNotified = true;
  await store.charges.update(charge);
  const toList = await adminEmails();
  if (toList.length) {
    const merchant = await store.merchants.byId(charge.merchantId);
    sendPendingTransferAlert(toList, {
      reference: charge.reference,
      amount: charge.amount,
      currency: charge.currency || 'GHS',
      merchantName: merchant ? merchant.businessName : 'Unknown',
    }).catch(err => console.warn('[transfer-alert]', err.message));
  }
  res.json({ ok: true });
}));

router.post('/admin/charges/:reference/mark-paid', requireAdminAuth, ah(async (req, res) => {
  const charge = await store.charges.byReference(req.params.reference);
  if (!charge) throw Object.assign(new Error('Charge not found.'), { status: 404 });
  if (charge.status === 'success') throw Object.assign(new Error('Charge is already marked as paid.'), { status: 409 });
  charge.status = 'success';
  charge.paidAt = Date.now();
  charge.method = charge.method || 'bank_transfer';
  charge.updatedAt = Date.now();
  charge.successEmailSent = true;
  /* Deliberate admin override — must land even against a concurrent poll. */
  await store.charges.forceUpdate(charge);
  const merchant = await store.merchants.byId(charge.merchantId);
  if (merchant) {
    webhooks.emit(merchant, 'charge.success', charge).catch(() => {});
    if ((charge.mode || 'test') === 'live') {
      const toList = await adminEmails();
      if (toList.length) {
        sendDepositAlert(toList, {
          reference: charge.reference,
          amount: charge.amount,
          currency: charge.currency || 'GHS',
          merchantName: merchant.businessName,
          customerEmail: charge.customerEmail,
          payerName: charge.payerName,
          method: charge.method,
        }).catch(err => console.warn('[deposit-alert]', err.message));
      }
    }
  }
  res.json({ charge });
}));

/* ========================= Nalopay integration ========================== */

async function emitWebhookIfTerminal(charge) {
  if (charge.status !== 'success' && charge.status !== 'failed') return;
  const merchant = await store.merchants.byId(charge.merchantId);
  if (!merchant) return;
  const type = charge.status === 'success' ? 'charge.success' : 'charge.failed';
  webhooks.emit(merchant, type, charge).catch(() => {});
  /* One alert per successful payment is the largest consumer of the email
     quota — on a busy day it can exhaust Resend's free 100/day and block
     signup OTPs. Set DEPOSIT_ALERTS=off to reserve the quota for OTPs. */
  const alertsOff = String(process.env.DEPOSIT_ALERTS || '').toLowerCase() === 'off';
  if (!alertsOff && charge.status === 'success' && !charge.successEmailSent && (charge.mode || 'test') === 'live') {
    charge.successEmailSent = true;
    await store.charges.update(charge);
    const toList = await adminEmails();
    if (toList.length) {
      sendDepositAlert(toList, {
        reference: charge.reference,
        amount: charge.amount,
        currency: charge.currency || 'GHS',
        merchantName: merchant.businessName,
        customerEmail: charge.customerEmail,
        payerName: charge.payerName,
        method: charge.method,
      }).catch(err => console.warn('[deposit-alert]', err.message));
    }
  }
}

function normalizePhone(raw) {
  const d = String(raw || '').replace(/\D/g, '');
  if (d.startsWith('233') && d.length >= 12) return d;
  if (d.startsWith('0') && d.length >= 10) return '233' + d.slice(1);
  return d;
}

/* Nalopay exposes three states only — PENDING / COMPLETED / FAILED. There is
   no OTP or PIN step: mobile money is approved on the payer's handset, and
   cards are handled on Nalopay's hosted page. Applies the terminal state to
   the charge and returns the `next` value the checkout UI expects. */
function applyNalopayStatus(charge, nalopayStatus, extra = {}) {
  const mapped = nalopay.mapStatus(nalopayStatus);
  const now = Date.now();

  /* Nalopay's status payload carries no decline reason, so record everything
     it does return. Without this a failed charge is just "Payment failed",
     which is undiagnosable after the fact. */
  if (extra.raw) {
    charge.nalopay = {
      status: nalopayStatus,
      reference: extra.raw.reference,
      charges: extra.raw.charges,
      amountAfterCharges: extra.raw.amount_after_charges,
      reportedAmount: extra.raw.amount,
      observedAt: now,
    };
  }

  /* Terminal states are final. A late or duplicate status check must never
     flip an already-paid charge to failed — that would silently erase a
     collected payment from the merchant's balance. */
  if (charge.status === 'success' || charge.status === 'failed') {
    return { next: charge.status };
  }

  if (mapped === 'success') {
    charge.status = 'success';
    charge.paidAt = now;
    charge.updatedAt = now;
    charge.resolvedInMs = charge.createdAt ? now - charge.createdAt : null;
    charge.auth = Object.assign({ provider: 'nalopay' }, charge.auth, extra.auth);
  } else if (mapped === 'failed') {
    charge.status = 'failed';
    charge.updatedAt = now;
    charge.resolvedInMs = charge.createdAt ? now - charge.createdAt : null;
    charge.failure = { message: extra.message || 'Payment failed', nalopayStatus };
  }
  return { next: mapped };
}

/* Upper bound on a single charge, in major units. Guards against overflow
   values (Infinity, 1e400) and typos with an extra three zeros. */
const MAX_AMOUNT_MAJOR = 1_000_000;

/* Nalopay network codes. Vodafone Ghana rebranded to Telecel — accept both. */
const NETWORKS = { MTN: 'MTN', VODAFONE: 'TELECEL', TELECEL: 'TELECEL', AIRTELTIGO: 'AT', AT: 'AT' };

function originOf(req) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  return `${proto}://${req.get('host')}`;
}
function nalopayCallbackUrl(req) { return `${originOf(req)}/api/webhooks/nalopay`; }

/* Pull our own charge reference back out of a callback. Collections echo
   `extra_data` verbatim; hosted checkout only echoes the product summary, so
   the reference is smuggled through a product's metadata. */
function cowrieRefFromCallback(body) {
  const ex = body && body.extra_data;
  if (!ex) return null;
  if (ex.cowrie_reference) return ex.cowrie_reference;
  if (Array.isArray(ex.products)) {
    for (const p of ex.products) {
      if (p && p.metadata && p.metadata.cowrie_reference) return p.metadata.cowrie_reference;
    }
  }
  return null;
}

router.post('/charges/:reference/pay', payLimiter, loadCharge, ah(async (req, res) => {
  const charge = req.charge;
  if (charge.status === 'success' || charge.status === 'failed') return res.json({ charge, next: charge.status });

  if (!nalopay.configured()) {
    const e = new Error('Nalopay is not configured.'); e.status = 503; throw e;
  }

  /* Nalopay has no sandbox: every collection hits the live account and moves
     real money. Under Paystack a test key meant a simulated charge, so a
     test-mode charge here would silently take real funds while being labelled
     "test". Refuse rather than let that happen. */
  if ((charge.mode || 'test') !== 'live') {
    const e = new Error(
      'Test mode is not available — the payment provider has no sandbox, so every charge moves real money. Use your live API key (pk_live_…).',
    );
    e.status = 400; throw e;
  }

  const { method, phone, provider, payerName } = req.body || {};
  if (payerName && String(payerName).trim()) { charge.payerName = String(payerName).trim(); }

  /* Nalopay treats `reference` as the idempotency key, so each attempt needs
     a fresh one. Keep it SHORT and in KassifyPay's native cwr_ format — Nalopay
     rejects long / underscore-heavy references, and a merchant's own
     charge.reference can be long (e.g. an integrator's cgw_… id). We map the
     attempt back to the charge via nalopayOrderId + cowrie_reference metadata. */
  const attemptRef = `cwr_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;

  if (method === 'mobile_money') {
    const network = NETWORKS[String(provider || '').toUpperCase()] || 'MTN';
    const account = normalizePhone(phone);
    if (account.length < 12) {
      const e = new Error('Mobile money number is invalid.'); e.status = 400; throw e;
    }
    const data = await nalopay.collection({
      accountNumber: account,
      accountName: charge.payerName || 'Customer',
      network,
      amountMinor: charge.amount,
      reference: attemptRef,
      callbackUrl: nalopayCallbackUrl(req),
      description: `KassifyPay ${charge.reference}`,
      extraData: { cowrie_reference: charge.reference },
    });
    console.log('[Nalopay /collection]', JSON.stringify({ ok: !!data.success, code: data.code, status: data.data && data.data.status, http: data.httpStatus }));
    if (!data.success || !data.data) {
      const msg = data.error ? `${data.error.description}` : (data.code || 'Charge failed');
      throw Object.assign(new Error(msg), { status: 400 });
    }
    /* Losing this write would strand the charge: without nalopayOrderId there
       is no way to poll Nalopay for the outcome, so a real payment could never
       be confirmed. Retry rather than write once and hope. */
    await saveChargeWithRetry(charge, (c) => {
      c.method = 'mobile_money';
      c.nalopayOrderId = data.data.order_id;
      c.nalopayRef = attemptRef;
      c.attemptCount = (c.attemptCount || 0) + 1;
      c.lastAttemptAt = Date.now();
      c.updatedAt = Date.now();
      c.auth = { provider: 'nalopay', channel: 'mobile_money', network, phone: account.slice(-10) };
    });
    /* Always PENDING here — the payer approves the prompt on their handset and
       the checkout polls. `otp_code` is a USSD string to dial, not an OTP. */
    return res.json({ charge, next: 'pending', detail: data.data.otp_code || null });
  }

  if (method === 'card') {
    const data = await nalopay.checkoutSession({
      orderId: attemptRef,
      customerName: charge.payerName || 'Customer',
      referralUrl: `${originOf(req)}/checkout?reference=${encodeURIComponent(charge.reference)}`,
      callbackUrl: nalopayCallbackUrl(req),
      reference: attemptRef,
      mode: 'CARD',
      products: [{
        name: `Payment ${charge.reference}`,
        count: 1,
        price: nalopay.toMajor(charge.amount),
        /* Only path back to our charge — checkout callbacks echo the summary,
           not the arbitrary extra_data that collections return. */
        metadata: { cowrie_reference: charge.reference },
      }],
      itemCount: 1,
      totalMinor: charge.amount,
    });
    console.log('[Nalopay /checkout]', JSON.stringify({ ok: !!data.success, code: data.code, http: data.httpStatus }));
    if (!data.success || !data.data || !data.data.checkout_url) {
      const msg = data.error ? `${data.error.description}` : (data.code || 'Checkout session failed');
      throw Object.assign(new Error(msg), { status: 400 });
    }
    await saveChargeWithRetry(charge, (c) => {
      c.method = 'card';
      c.nalopayRef = attemptRef;
      c.attemptCount = (c.attemptCount || 0) + 1;
      c.lastAttemptAt = Date.now();
      c.updatedAt = Date.now();
      c.auth = { provider: 'nalopay', channel: 'card' };
    });
    /* Hosted page is a full redirect — there is no inline/access-code mode. */
    return res.json({ charge, next: 'redirect', detail: data.data.checkout_url });
  }

  const e = new Error('Nalopay supports mobile money and card payments only.');
  e.status = 400; throw e;
}));

/* store.charges.update() is version-checked and returns null when another
   writer got there first. `apply` is re-run against a freshly loaded copy on
   each attempt, so it must be safe to repeat — applyNalopayStatus is, because
   it refuses to change an already-terminal charge. The caller's object is
   updated in place with whatever finally landed. */
async function saveChargeWithRetry(charge, apply, attempts = 4) {
  let current = charge;
  for (let i = 0; i < attempts; i++) {
    const result = apply(current);
    if (await store.charges.update(current)) {
      if (current !== charge) Object.assign(charge, current);
      return result;
    }
    const fresh = await store.charges.byReference(charge.reference);
    if (!fresh) return null;           // charge deleted underneath us
    current = fresh;
  }
  const e = new Error('This charge is being updated, please try again.');
  e.status = 409; throw e;
}

/* Confirms a charge against Nalopay's own record. Never trusts a status that
   arrived over the wire — the order_id is looked up server-side. */
async function confirmWithNalopay(charge, orderId) {
  const id = orderId || charge.nalopayOrderId;
  if (!id) return { next: 'pending' };
  const data = await nalopay.collectionStatus(id);
  if (!data.success || !data.data) return { next: 'pending' };

  const result = await saveChargeWithRetry(charge, (c) => {
    if (!c.nalopayOrderId) c.nalopayOrderId = id;
    return applyNalopayStatus(c, data.data.status, { raw: data.data });
  });
  if (!result) return { next: 'pending' };
  await emitWebhookIfTerminal(charge);
  return result;
}

router.get('/charges/:reference/poll', payLimiter, loadCharge, ah(async (req, res) => {
  const charge = req.charge;
  if (charge.status === 'success' || charge.status === 'failed') return res.json({ charge, next: charge.status });
  const result = await confirmWithNalopay(charge);
  res.json({ charge, next: result.next });
}));

/* Called when the shopper returns from the hosted checkout page. */
router.get('/charges/:reference/verify', payLimiter, loadCharge, ah(async (req, res) => {
  const charge = req.charge;
  if (charge.status === 'success' || charge.status === 'failed') return res.json({ charge });
  await confirmWithNalopay(charge);
  res.json({ charge });
}));

/* Nalopay callbacks carry NO signature, so the body is treated as an untrusted
   nudge: it tells us which order to look at, and nothing more. The status is
   always re-fetched from Nalopay before a charge is marked paid. Without this,
   anyone who learns the callback URL could POST a forged COMPLETED. */
router.post('/webhooks/nalopay', ah(async (req, res) => {
  const body = req.body || {};
  const orderId = body.order_id;
  const cowrieRef = cowrieRefFromCallback(body);
  console.log('[Nalopay callback]', JSON.stringify({ orderId, claimed: body.status, ref: cowrieRef }));

  if (!orderId || !cowrieRef) return res.json({ received: true });

  const charge = await store.charges.byReference(cowrieRef);
  if (!charge) return res.json({ received: true });
  if (charge.status === 'success' || charge.status === 'failed') return res.json({ received: true });

  await confirmWithNalopay(charge, orderId);
  res.json({ received: true });
}));

/* ========================= KYC ========================= */

router.post('/kyc', requireAuth, ah(async (req, res) => {
  const merchant = req.merchant;
  if (merchant.kycStatus === 'approved') {
    const e = new Error('Your account is already verified.'); e.status = 409; throw e;
  }
  const { fullName, phone, idType, idNumber, businessType, businessRegNumber, address, idFront, idBack, certificate } = req.body || {};
  if (!fullName || !phone || !idType || !idNumber || !address) {
    const e = new Error('fullName, phone, idType, idNumber and address are required.'); e.status = 400; throw e;
  }
  if (!idFront || !idBack) {
    const e = new Error('Front and back photos of your ID are required.'); e.status = 400; throw e;
  }
  if (!certificate) {
    const e = new Error('Business certificate or registration document is required.'); e.status = 400; throw e;
  }
  const MAX = 7 * 1024 * 1024; // base64 of a 5 MB file is ~6.7 MB; allow headroom
  for (const [label, val] of [['idFront', idFront], ['idBack', idBack], ['certificate', certificate]]) {
    if (typeof val !== 'string' || !val.startsWith('data:')) {
      const e = new Error(`${label} must be a valid data URL.`); e.status = 400; throw e;
    }
    if (val.length > MAX) {
      const e = new Error(`${label} exceeds the 5 MB limit.`); e.status = 400; throw e;
    }
  }
  /* Upload images to Cloudinary if configured; fall back to storing base64 */
  async function maybeUpload(dataUrl) {
    try {
      const url = await cloudinary.upload(dataUrl);
      return url || dataUrl;
    } catch (err) {
      console.warn('[KYC] Cloudinary upload failed, storing base64:', err.message);
      return dataUrl;
    }
  }
  const [storedFront, storedBack, storedCert] = await Promise.all([
    maybeUpload(idFront),
    maybeUpload(idBack),
    maybeUpload(certificate),
  ]);

  merchant.kycStatus = 'pending';
  merchant.kycData = {
    fullName: String(fullName).trim(),
    phone: String(phone).trim(),
    idType: String(idType).trim(),
    idNumber: String(idNumber).trim(),
    businessType: String(businessType || 'individual').trim(),
    businessRegNumber: String(businessRegNumber || '').trim(),
    address: String(address).trim(),
    idFront: storedFront,
    idBack: storedBack,
    certificate: storedCert,
  };
  merchant.kycSubmittedAt = Date.now();
  merchant.kycRejectionReason = null;
  await store.merchants.update(merchant);
  res.json({ merchant: publicMerchant(merchant) });
}));

router.get('/kyc', requireAuth, (req, res) => {
  const { kycStatus, kycData, kycSubmittedAt, kycReviewedAt, kycRejectionReason } = req.merchant;
  res.json({ kycStatus: kycStatus || 'none', kycData: kycData || null, kycSubmittedAt, kycReviewedAt, kycRejectionReason });
});

router.get('/admin/kyc', requireAdminAuth, ah(async (req, res) => {
  const all = await store.merchants.all();
  const merchants = all.filter(m => !m.demo).map(m => ({
    id: m.id, businessName: m.businessName, email: m.email,
    kycStatus: m.kycStatus || 'none', kycData: m.kycData || null,
    kycSubmittedAt: m.kycSubmittedAt, kycReviewedAt: m.kycReviewedAt,
    kycRejectionReason: m.kycRejectionReason,
  }));
  res.json({ merchants });
}));

router.post('/admin/kyc/:merchantId/approve', requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  if (!merchant) { const e = new Error('Merchant not found.'); e.status = 404; throw e; }
  merchant.kycStatus = 'approved';
  merchant.kycReviewedAt = Date.now();
  merchant.kycRejectionReason = null;
  await store.merchants.update(merchant);
  sendKycApproved(merchant.email, merchant.businessName).catch(() => {});
  res.json({ merchant: publicMerchant(merchant) });
}));

router.post('/admin/kyc/:merchantId/reject', requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  if (!merchant) { const e = new Error('Merchant not found.'); e.status = 404; throw e; }
  const reason = String((req.body || {}).reason || '').trim() || 'Your submission did not meet our requirements.';
  merchant.kycStatus = 'rejected';
  merchant.kycReviewedAt = Date.now();
  merchant.kycRejectionReason = reason;
  await store.merchants.update(merchant);
  sendKycRejected(merchant.email, merchant.businessName, reason).catch(() => {});
  res.json({ merchant: publicMerchant(merchant) });
}));

/* ==================== Gateway Settings (Admin) ==================== */

const SUPPORTED_GATEWAYS = [
  /* ── Fully integrated ─────────────────────────────────────────────── */
  /* Nalopay has no test/live key split — it uses a merchant_id + Basic token
     + secret key triple. The four generic slots are reused; the secret-bearing
     values must sit in *SecretKey fields because only those are masked. */
  { id: 'nalopay',       name: 'Nalopay',        status: 'integrated',   website: 'https://merchant.nalopay.com',   fields: { testPublicKey: 'Merchant ID',                        testSecretKey: 'Basic Auth token',                    livePublicKey: 'Not used — leave blank',             liveSecretKey: 'Secret key (for signing)' } },
  { id: 'paystack',      name: 'Paystack',       status: 'configurable', website: 'https://paystack.com',           fields: { testPublicKey: 'Test public key (pk_test_…)',        testSecretKey: 'Test secret key (sk_test_…)',         livePublicKey: 'Live public key (pk_live_…)',        liveSecretKey: 'Live secret key (sk_live_…)' } },

  /* ── Global ────────────────────────────────────────────────────────── */
  { id: 'stripe',        name: 'Stripe',          status: 'configurable', website: 'https://stripe.com',             fields: { testPublicKey: 'Test publishable key (pk_test_…)',  testSecretKey: 'Test secret key (sk_test_…)',         livePublicKey: 'Live publishable key (pk_live_…)',   liveSecretKey: 'Live secret key (sk_live_…)' } },
  { id: 'paypal',        name: 'PayPal',          status: 'configurable', website: 'https://developer.paypal.com',   fields: { testPublicKey: 'Sandbox client ID',                 testSecretKey: 'Sandbox client secret',               livePublicKey: 'Live client ID',                     liveSecretKey: 'Live client secret' } },
  { id: 'braintree',     name: 'Braintree',       status: 'configurable', website: 'https://braintreepayments.com',  fields: { testPublicKey: 'Sandbox merchant ID',               testSecretKey: 'Sandbox private key',                 livePublicKey: 'Production merchant ID',              liveSecretKey: 'Production private key' } },
  { id: 'adyen',         name: 'Adyen',           status: 'configurable', website: 'https://adyen.com',              fields: { testPublicKey: 'Test API key',                      testSecretKey: 'Test HMAC key',                       livePublicKey: 'Live API key',                        liveSecretKey: 'Live HMAC key' } },
  { id: 'checkoutcom',   name: 'Checkout.com',    status: 'configurable', website: 'https://checkout.com',           fields: { testPublicKey: 'Test public key (pk_test_…)',       testSecretKey: 'Test secret key (sk_test_…)',         livePublicKey: 'Live public key (pk_…)',              liveSecretKey: 'Live secret key (sk_…)' } },
  { id: 'worldpay',      name: 'Worldpay',        status: 'configurable', website: 'https://worldpay.com',           fields: { testPublicKey: 'Test client key',                   testSecretKey: 'Test service key',                    livePublicKey: 'Live client key',                     liveSecretKey: 'Live service key' } },
  { id: 'authorizenet',  name: 'Authorize.Net',   status: 'configurable', website: 'https://authorize.net',          fields: { testPublicKey: 'Test API login ID',                 testSecretKey: 'Test transaction key',                livePublicKey: 'Live API login ID',                   liveSecretKey: 'Live transaction key' } },
  { id: 'square',        name: 'Square',          status: 'configurable', website: 'https://squareup.com',           fields: { testPublicKey: 'Sandbox application ID',            testSecretKey: 'Sandbox access token',                livePublicKey: 'Production application ID',           liveSecretKey: 'Production access token' } },
  { id: 'twocheckout',   name: '2Checkout',       status: 'configurable', website: 'https://2checkout.com',          fields: { testPublicKey: 'Test merchant code',                testSecretKey: 'Test secret key',                     livePublicKey: 'Live merchant code',                  liveSecretKey: 'Live secret key' } },
  { id: 'klarna',        name: 'Klarna',          status: 'configurable', website: 'https://klarna.com',             fields: { testPublicKey: 'Playground username (UID)',         testSecretKey: 'Playground password',                 livePublicKey: 'Production username (UID)',            liveSecretKey: 'Production password' } },
  { id: 'mollie',        name: 'Mollie',          status: 'configurable', website: 'https://mollie.com',             fields: { testPublicKey: 'Test API key (test_…)',             testSecretKey: 'Test API key (same field)',            livePublicKey: 'Live API key (live_…)',               liveSecretKey: 'Live API key (same field)' } },
  { id: 'nuvei',         name: 'Nuvei',           status: 'configurable', website: 'https://nuvei.com',              fields: { testPublicKey: 'Test merchant ID',                  testSecretKey: 'Test merchant site secret key',       livePublicKey: 'Live merchant ID',                    liveSecretKey: 'Live merchant site secret key' } },
  { id: 'paysafe',       name: 'Paysafe',         status: 'configurable', website: 'https://paysafe.com',            fields: { testPublicKey: 'Test API key',                      testSecretKey: 'Test single-use token API key',       livePublicKey: 'Live API key',                        liveSecretKey: 'Live single-use token API key' } },
  { id: 'aeropay',       name: 'Aeropay',         status: 'configurable', website: 'https://aeropay.com',            fields: { testPublicKey: 'Test client ID',                    testSecretKey: 'Test client secret',                  livePublicKey: 'Live client ID',                      liveSecretKey: 'Live client secret' } },
  { id: 'amazonpay',     name: 'Amazon Pay',      status: 'configurable', website: 'https://pay.amazon.com',         fields: { testPublicKey: 'Sandbox merchant ID',               testSecretKey: 'Sandbox MWS auth token',              livePublicKey: 'Production merchant ID',              liveSecretKey: 'Production MWS auth token' } },

  /* ── Africa ────────────────────────────────────────────────────────── */
  { id: 'flutterwave',   name: 'Flutterwave',     status: 'configurable', website: 'https://flutterwave.com',        fields: { testPublicKey: 'Test public key (FLWPUBK_TEST-…)', testSecretKey: 'Test secret key (FLWSECK_TEST-…)',   livePublicKey: 'Live public key (FLWPUBK-…)',        liveSecretKey: 'Live secret key (FLWSECK-…)' } },
  { id: 'monnify',       name: 'Monnify',         status: 'configurable', website: 'https://monnify.com',            fields: { testPublicKey: 'Test API key',                      testSecretKey: 'Test secret key',                     livePublicKey: 'Live API key',                        liveSecretKey: 'Live secret key' } },
  { id: 'interswitch',   name: 'Interswitch',     status: 'configurable', website: 'https://developer.interswitch.com', fields: { testPublicKey: 'Test client ID',               testSecretKey: 'Test client secret',                  livePublicKey: 'Live client ID',                      liveSecretKey: 'Live client secret' } },
  { id: 'peachpayments', name: 'Peach Payments',  status: 'configurable', website: 'https://peachpayments.com',      fields: { testPublicKey: 'Test entity ID',                    testSecretKey: 'Test API key',                        livePublicKey: 'Live entity ID',                      liveSecretKey: 'Live API key' } },
  { id: 'payfast',       name: 'PayFast',         status: 'configurable', website: 'https://payfast.io',             fields: { testPublicKey: 'Test merchant ID',                  testSecretKey: 'Test merchant key',                   livePublicKey: 'Live merchant ID',                    liveSecretKey: 'Live merchant key' } },
  { id: 'ozow',          name: 'Ozow',            status: 'configurable', website: 'https://ozow.com',               fields: { testPublicKey: 'Test site code',                    testSecretKey: 'Test private key',                    livePublicKey: 'Live site code',                      liveSecretKey: 'Live private key' } },
  { id: 'dpopay',        name: 'DPO Pay',         status: 'configurable', website: 'https://dpopay.com',             fields: { testPublicKey: 'Test company token',                testSecretKey: 'Test service type code',              livePublicKey: 'Live company token',                  liveSecretKey: 'Live service type code' } },
  { id: 'pesapal',       name: 'Pesapal',         status: 'configurable', website: 'https://pesapal.com',            fields: { testPublicKey: 'Sandbox consumer key',              testSecretKey: 'Sandbox consumer secret',             livePublicKey: 'Live consumer key',                   liveSecretKey: 'Live consumer secret' } },
  { id: 'cellulant',     name: 'Cellulant / Tingg', status: 'configurable', website: 'https://cellulant.io',        fields: { testPublicKey: 'Test access key',                   testSecretKey: 'Test secret key',                     livePublicKey: 'Live access key',                     liveSecretKey: 'Live secret key' } },
  { id: 'fawry',         name: 'Fawry',           status: 'configurable', website: 'https://developer.fawrystaging.com', fields: { testPublicKey: 'Test merchant code',           testSecretKey: 'Test security key',                   livePublicKey: 'Live merchant code',                  liveSecretKey: 'Live security key' } },
  { id: 'vodapay',       name: 'VodaPay',         status: 'configurable', website: 'https://vodapay.vodacom.co.za',  fields: { testPublicKey: 'Staging app ID',                    testSecretKey: 'Staging app secret',                  livePublicKey: 'Production app ID',                   liveSecretKey: 'Production app secret' } },
  { id: 'ipay',          name: 'iPay Africa',     status: 'configurable', website: 'https://ipayafrica.com',         fields: { testPublicKey: 'Test vendor ID',                    testSecretKey: 'Test hash key',                       livePublicKey: 'Live vendor ID',                       liveSecretKey: 'Live hash key' } },

  /* ── Middle East ────────────────────────────────────────────────────── */
  { id: 'tap',           name: 'Tap Payments',    status: 'configurable', website: 'https://tap.company',            fields: { testPublicKey: 'Test public key (pk_test_…)',       testSecretKey: 'Test secret key (sk_test_…)',         livePublicKey: 'Live public key (pk_live_…)',        liveSecretKey: 'Live secret key (sk_live_…)' } },
  { id: 'paytabs',       name: 'PayTabs',         status: 'configurable', website: 'https://paytabs.com',            fields: { testPublicKey: 'Test profile ID',                   testSecretKey: 'Test server key',                     livePublicKey: 'Live profile ID',                     liveSecretKey: 'Live server key' } },

  /* ── Asia / India ───────────────────────────────────────────────────── */
  { id: 'razorpay',      name: 'Razorpay',        status: 'configurable', website: 'https://razorpay.com',           fields: { testPublicKey: 'Test key ID (rzp_test_…)',          testSecretKey: 'Test key secret',                     livePublicKey: 'Live key ID (rzp_live_…)',            liveSecretKey: 'Live key secret' } },
  { id: 'payu',          name: 'PayU',            status: 'configurable', website: 'https://payu.com',               fields: { testPublicKey: 'Test merchant key',                 testSecretKey: 'Test merchant salt',                  livePublicKey: 'Live merchant key',                   liveSecretKey: 'Live merchant salt' } },
  { id: 'ccavenue',      name: 'CCAvenue',        status: 'configurable', website: 'https://ccavenue.com',           fields: { testPublicKey: 'Test merchant ID',                  testSecretKey: 'Test working key',                    livePublicKey: 'Live merchant ID',                    liveSecretKey: 'Live working key' } },
  { id: 'cashfree',      name: 'Cashfree',        status: 'configurable', website: 'https://cashfree.com',           fields: { testPublicKey: 'Test app ID',                       testSecretKey: 'Test secret key',                     livePublicKey: 'Live app ID',                         liveSecretKey: 'Live secret key' } },
  { id: 'paymongo',      name: 'PayMongo',        status: 'configurable', website: 'https://paymongo.com',           fields: { testPublicKey: 'Test public key (pk_test_…)',       testSecretKey: 'Test secret key (sk_test_…)',         livePublicKey: 'Live public key (pk_live_…)',        liveSecretKey: 'Live secret key (sk_live_…)' } },
  /* ── Additional Africa ─────────────────────────────────────────────── */
  { id: 'moolre',        name: 'Moolre',          status: 'configurable', website: 'https://moolre.com',             fields: { testPublicKey: 'Test public key',                    testSecretKey: 'Test secret key',                     livePublicKey: 'Live public key',                    liveSecretKey: 'Live secret key' } },
  { id: 'fincra',        name: 'Fincra',          status: 'configurable', website: 'https://fincra.com',             fields: { testPublicKey: 'Test public key',                    testSecretKey: 'Test secret key',                     livePublicKey: 'Live public key',                    liveSecretKey: 'Live secret key' } },
  { id: 'bani',          name: 'Bani',            status: 'configurable', website: 'https://getbani.com',            fields: { testPublicKey: 'Test public key',                    testSecretKey: 'Test secret key',                     livePublicKey: 'Live public key',                    liveSecretKey: 'Live secret key' } },
  { id: 'korapay',       name: 'Korapay',         status: 'configurable', website: 'https://korapay.com',            fields: { testPublicKey: 'Test public key (pk_test_…)',        testSecretKey: 'Test secret key (sk_test_…)',          livePublicKey: 'Live public key (pk_live_…)',         liveSecretKey: 'Live secret key (sk_live_…)' } },
];

/* Maps the four generic key slots onto Nalopay's credential triple.
   Returns null when incomplete so the env vars stay in charge. */
function nalopayKeysFrom(g) {
  if (!g) return null;
  const keys = { merchantId: g.testPublicKey || '', basicAuth: g.testSecretKey || '', secretKey: g.liveSecretKey || '' };
  return (keys.merchantId && keys.basicAuth && keys.secretKey) ? keys : null;
}

function maskSecret(val) {
  if (!val || val.length < 8) return val || '';
  return val.slice(0, 8) + '•'.repeat(Math.min(val.length - 8, 24));
}

router.get('/admin/gateways', requireAdminAuth, ah(async (req, res) => {
  const gs = (await store.settings.get('gateways')) || { activeGateway: null, installed: [], gateways: {} };
  const installed = (gs.installed || []).map(id => {
    const meta = SUPPORTED_GATEWAYS.find(g => g.id === id);
    if (!meta) return null;
    const keys = (gs.gateways && gs.gateways[id]) || {};
    return {
      ...meta,
      active: gs.activeGateway === id,
      keys: {
        testPublicKey: keys.testPublicKey || '',
        testSecretKey: maskSecret(keys.testSecretKey),
        livePublicKey: keys.livePublicKey || '',
        liveSecretKey: maskSecret(keys.liveSecretKey),
      },
    };
  }).filter(Boolean);
  res.json({
    activeGateway: gs.activeGateway || null,
    installed,
    supported: SUPPORTED_GATEWAYS.map(g => ({ id: g.id, name: g.name, fields: g.fields })),
  });
}));

router.put('/admin/gateways/:id', requireAdminAuth, ah(async (req, res) => {
  const { id } = req.params;
  if (!SUPPORTED_GATEWAYS.find(g => g.id === id)) {
    const e = new Error('Unknown gateway.'); e.status = 400; throw e;
  }
  const { testPublicKey = '', testSecretKey = '', livePublicKey = '', liveSecretKey = '' } = req.body || {};
  const gs = (await store.settings.get('gateways')) || { activeGateway: null, installed: [], gateways: {} };
  const existing = (gs.gateways && gs.gateways[id]) || {};

  gs.gateways = gs.gateways || {};
  gs.installed = gs.installed || [];
  if (!gs.installed.includes(id)) gs.installed.push(id);

  gs.gateways[id] = {
    testPublicKey: testPublicKey || existing.testPublicKey || '',
    testSecretKey: testSecretKey && !testSecretKey.includes('•') ? testSecretKey : (existing.testSecretKey || ''),
    livePublicKey: livePublicKey || existing.livePublicKey || '',
    liveSecretKey: liveSecretKey && !liveSecretKey.includes('•') ? liveSecretKey : (existing.liveSecretKey || ''),
  };
  await store.settings.set('gateways', gs);
  if (id === 'nalopay') nalopay.configureKeys(nalopayKeysFrom(gs.gateways.nalopay));
  res.json({ ok: true });
}));

router.put('/admin/gateways/:id/toggle', requireAdminAuth, ah(async (req, res) => {
  const { id } = req.params;
  if (!SUPPORTED_GATEWAYS.find(g => g.id === id)) {
    const e = new Error('Unknown gateway.'); e.status = 400; throw e;
  }
  const gs = (await store.settings.get('gateways')) || { activeGateway: null, installed: [], gateways: {} };
  gs.activeGateway = gs.activeGateway === id ? null : id;
  await store.settings.set('gateways', gs);
  if (gs.activeGateway === 'nalopay') nalopay.configureKeys(nalopayKeysFrom((gs.gateways || {}).nalopay));
  else if (id === 'nalopay') nalopay.configureKeys(null);
  res.json({ ok: true, activeGateway: gs.activeGateway });
}));

router.delete('/admin/gateways/:id', requireAdminAuth, ah(async (req, res) => {
  const { id } = req.params;
  const gs = (await store.settings.get('gateways')) || { activeGateway: null, installed: [], gateways: {} };
  gs.installed = (gs.installed || []).filter(x => x !== id);
  if (gs.activeGateway === id) gs.activeGateway = null;
  if (gs.gateways) delete gs.gateways[id];
  await store.settings.set('gateways', gs);
  if (id === 'nalopay') nalopay.configureKeys(null);
  res.json({ ok: true });
}));

module.exports = router;
