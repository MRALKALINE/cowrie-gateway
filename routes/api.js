'use strict';
const express = require('express');
const store = require('../lib/store');
const cfg = require('../lib/config');
const payments = require('../lib/payments');
const nalopay = require('../lib/nalopay');
const mcash = require('../lib/mcash');
const webhooks = require('../lib/webhooks');
const { sendOtp, sendKycApproved, sendKycRejected, sendPendingTransferAlert, sendDepositAlert, sendMerchantDepositNotice, sendPayoutRequestAlert, sendSupportMessageAlert, sendSupportReplyNotice } = require('../lib/email');
const fx = require('../lib/fx');
const fees = require('../lib/fees');
const partners = require('../lib/partners');
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

/* ── rate limiters ──
   The implementation lives in lib/ratelimit so the hosted partner links, which
   are routed outside /api, are capped by the same one. */
const { rateLimit } = require('../lib/ratelimit');
const globalLimiter = rateLimit({ windowMs: 60_000, max: 200 }); // all routes
const authLimiter   = rateLimit({ windowMs: 60_000, max: 10  }); // login / register
const chargeLimiter = rateLimit({ windowMs: 60_000, max: 60  }); // charge creation
const payLimiter    = rateLimit({ windowMs: 60_000, max: 20  }); // payment actions
/* The Nalopay callback is unauthenticated and every call makes us hit their
   API to verify the status, so an unbounded flood becomes an amplifier
   against our own gateway account as well as this server. */
const webhookLimiter = rateLimit({ windowMs: 60_000, max: 120 });
/* Each support message writes a row and can trigger an email. */
const supportLimiter = rateLimit({ windowMs: 60_000, max: 12  });
/* KYC accepts megabytes of base64 per submission. */
const kycLimiter     = rateLimit({ windowMs: 60_000, max: 5   });
/* Blanket cap on authenticated writes so one compromised session cannot
   hammer the database. Generous enough not to interrupt real use. */
const writeLimiter   = rateLimit({ windowMs: 60_000, max: 90  });

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
    /* A deactivated merchant is deliberately let through. Refusing the session
       outright left them with a bare error and no way to learn why, so they
       can now sign in, see the reason and read their own records. Anything
       that moves money is stopped by requireActive below. */
    req.merchant = merchant;
    req.mode = (req.headers['x-cowrie-mode'] === 'live') ? 'live' : 'test';
    next();
  } catch (e) { next(e); }
}

/* Blocks anything that moves money or changes settings for a deactivated
   merchant. requireAuth now lets them in so they can read their records and
   see why; this is what actually enforces the deactivation. */
function requireActive(req, res, next) {
  if (req.merchant && req.merchant.locked) {
    const e = new Error(req.merchant.lockReason
      ? `Your account has been deactivated: ${req.merchant.lockReason}`
      : 'Your account has been deactivated. Please contact support.');
    e.status = 403; return next(e);
  }
  next();
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
    /* Live keys are issued at registration, and mode was taken purely from the
       key prefix — so an unverified merchant could collect real money simply by
       using their live key, bypassing the KYC gate the dashboard enforces on
       the mode switch. Verification is the point at which a merchant is allowed
       real funds, so it is checked here too. */
    if (isLive && merchant.kycStatus !== 'approved') {
      const e = new Error('Live payments require a verified account. Complete verification in your dashboard, or use your test keys.');
      e.status = 403; return next(e);
    }
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
  /* Deactivated accounts may sign in. The dashboard reads `locked` and
     `lockReason` from the merchant below and shows why; blocking here told
     them nothing and gave them nowhere to look. */
  const ttl = remember ? cfg.REMEMBER_TTL_MS : cfg.TOKEN_TTL_MS;
  const token = signToken({ sub: merchant.id, exp: Date.now() + ttl });
  res.json({ token, merchant: publicMerchant(merchant) });
}));

router.get('/me', requireAuth, (req, res) => {
  res.json({ merchant: publicMerchant(req.merchant) });
});

/* Which processor actually collects the money. The admin's explicit toggle
   wins; otherwise MCASH is preferred whenever it has credentials, with
   Nalopay as the fallback so old deployments keep working unchanged. */
async function activeProvider() {
  const gs = (await store.settings.get('gateways')) || {};
  if (gs.activeGateway === 'nalopay') return 'nalopay';
  if (gs.activeGateway === 'mcash') return 'mcash';
  /* The pay-link needs no keys, so MCASH is usable — and the default —
     even with nothing configured. */
  return (mcash.configured() || mcash.sandboxConfigured() || mcash.paylinkUrl()) ? 'mcash' : 'nalopay';
}

/* Public config — tells the checkout whether a gateway is wired up and which
   provider it is (the MCASH flow is a hosted redirect, so the checkout skips
   the phone-number step). MCASH_TEST_MODE / NALOPAY_TEST_MODE force the
   test banner on. */
router.get('/info', ah(async (req, res) => {
  const provider = await activeProvider();
  const testMode = provider === 'mcash'
    ? ((!mcash.configured() && !mcash.paylinkUrl()) || process.env.MCASH_TEST_MODE === 'true')
    : (!nalopay.configured() || process.env.NALOPAY_TEST_MODE === 'true');
  /* paylink tells the checkout live payments go through the static MCASH
     pay-link (momo only, manual confirmation) rather than hosted checkout. */
  const paylink = provider === 'mcash' && !mcash.configured() && !!mcash.paylinkUrl();
  res.json({ testMode, provider, paylink });
}));

router.put('/me/webhook', writeLimiter, requireAuth, requireActive, ah(async (req, res) => {
  const { url } = req.body || {};
  if (url) assertWebUrl(url, 'webhook url');
  req.merchant.webhookUrl = url || null;
  await store.merchants.update(req.merchant);
  res.json({ merchant: publicMerchant(req.merchant) });
}));

router.put('/me/website', writeLimiter, requireAuth, requireActive, ah(async (req, res) => {
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

router.delete('/transactions', writeLimiter, requireAuth, requireActive, ah(async (req, res) => {
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

router.post('/payment-links', writeLimiter, requireAuth, requireActive, chargeLimiter, ah(async (req, res) => {
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
  /* An open-amount charge has no amount until now, so the fee is computed the
     moment one is chosen — at the rate recorded when the charge was raised,
     not whatever the merchant's rate happens to be by the time the payer
     types a figure. */
  fees.applyFee(charge, charge.feeBps);
  /* The commission was nil while the amount was, so it is worked out at the
     rate attached when the link was followed. */
  partners.recompute(charge);
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
  /* A deposit brought in by a partner is tagged here, so the merchant only
     has to append their partner's code to a call they already make.

     An unrecognised code does not fail the deposit — losing a real payment to
     a typo would be far worse than losing the attribution — but it is recorded
     so it shows up in the console instead of vanishing. */
  const code = partners.codeFrom(req.body, req.query);
  let credited = null;
  if (code) {
    const named = partners.byCode(req.merchant, code);
    if (named && named.active !== false) credited = named;
    else charge.partnerCodeUnknown = partners.normaliseCode(code);
  }
  /* No code, or one nobody recognises — fall back to the merchant's own user
     id. Agrah sends metadata.userId on every deposit and knows which partner
     signed each user up, so a mapping held here credits the right person
     without their integration changing at all. */
  if (!credited) {
    credited = partners.byUserId(req.merchant, partners.userIdOf(charge));
  }
  if (credited) partners.attach(charge, credited);
  if (credited || charge.partnerCodeUnknown) await store.charges.update(charge);

  res.status(201).json({ charge, checkout_url: checkoutUrlFor(req, charge) });
}));

router.get('/charges/:reference', loadCharge, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.charge.merchantId);
  const c = req.charge;
  /* A charge reference is a capability: it travels in URLs, browser history and
     anywhere the payer forwards the link. Spreading the whole record handed
     everyone holding one the payer's phone number and email, the gateway's
     order ids, the merchant's metadata and the idempotency key. Only what the
     checkout actually renders is returned. */
  res.json({ charge: {
    reference: c.reference,
    amount: c.amount,                       // what the merchant receives
    feeAmount: c.feeAmount || 0,            // platform fee added on top
    totalAmount: fees.payableAmount(c),     // what the payer is charged
    feeBps: c.feeBps || 0,
    currency: c.currency,
    status: c.status,
    method: c.method,
    openAmount: !!c.openAmount,
    callbackUrl: c.callbackUrl || null,
    nalopayRef: c.nalopayRef || null,   // the checkout uses this to re-verify on return
    mcashRef: c.mcashRef || null,       // same job for the MCASH hosted flow
    mcashPaylink: !!c.mcashPaylink,     // reopening the link resumes polling, which retries the match
    ussdCode: c.ussdCode || null,       // dial-to-approve string, when the network gives one
    failure: c.failure ? { message: c.failure.message } : null,
    auth: c.auth ? { channel: c.auth.channel, network: c.auth.network, brand: c.auth.brand, last4: c.auth.last4 } : null,
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

router.put('/admin/password', writeLimiter, requireAdminAuth, ah(async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!(await findAdmin(req.adminEmail, currentPassword))) {
    const e = new Error('Current password is incorrect.'); e.status = 401; throw e;
  }
  await setPassword(req.adminEmail, newPassword);
  res.json({ ok: true });
}));

router.post('/admin/admins', writeLimiter, requireAdminAuth, ah(async (req, res) => {
  const { email, password } = req.body || {};
  await setPassword(email, password);
  res.status(201).json({ ok: true, email: String(email).trim().toLowerCase() });
}));

router.delete('/admin/admins/:email', writeLimiter, requireAdminAuth, ah(async (req, res) => {
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
  /* Fees are what the platform keeps: charged on top of the merchant's amount,
     so they are counted separately and never appear in merchant revenue. Older
     charges predate the field and contribute nothing. */
  const feesCollected = liveSuccess.reduce((s, c) => s + toGhs(c.feeAmount || 0, c.currency), 0);
  const testCollected  = testSuccess.reduce((s, c) => s + toGhs(c.amount, c.currency), 0);
  const totalPaidOut   = allPayouts.filter((p) => p.status === 'completed').reduce((s, p) => s + p.amount, 0);
  const totalCollected = Math.max(0, grossCollected - totalPaidOut);
  const paidOutToday = allPayouts.filter((p) => p.createdAt >= todayTs && p.status === 'completed').reduce((s, p) => s + p.amount, 0);
  const total = allCharges.length;
  const successRate = total > 0 ? ((successAll.length / total) * 100).toFixed(1) : '100.0';
  const pendingCount = allCharges.filter((c) => !['success', 'failed'].includes(c.status)).length;
  const allMerchants = await store.merchants.all();
  const merchantCount = allMerchants.filter((m) => !m.demo).length;


  /* Daily live revenue, newest first: index 0 is today, 1 yesterday, and so
     on. Drives both the period selector and the bar chart, so the two cannot
     disagree. Live-only and dated by paidAt, matching every other revenue
     figure on the dashboard. */
  const revenueByDay = [];
  for (let i = 0; i < 7; i++) {
    const d = new Date(); d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - i);
    const start = d.getTime(); const end = start + 86_400_000;
    const inDay = liveSuccess.filter((c) => {
      const at = c.paidAt || c.createdAt;
      return at >= start && at < end;
    });
    revenueByDay.push({
      date: d.toISOString().slice(0, 10),
      label: d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' }),
      amount: inDay.reduce((s, c) => s + toGhs(c.amount, c.currency), 0),
      fee: inDay.reduce((s, c) => s + toGhs(c.feeAmount || 0, c.currency), 0),
      count: inDay.length,
    });
  }

  const byMethod = {};
  successAll.forEach((c) => { const m = c.method || 'unknown'; byMethod[m] = (byMethod[m] || 0) + toGhs(c.amount, c.currency); });

  /* grossCollected is all-time live revenue before payouts; totalCollected is
     what remains after them. Both are useful and they answer different
     questions — "how much has this gateway processed" versus "how much is
     still held" — so return both rather than only the net figure. */
  res.json({
    overview: {
      collectedToday, collectedTodayCount, paidOutToday,
      grossCollected, feesCollected, totalPaidOut, liveCount: liveSuccess.length,
      totalCollected, testCollected, merchantCount, successRate, pendingCount,
      revenueByDay, byMethod,
    },
  });
}));

router.get('/admin/members', requireAdminAuth, ah(async (req, res) => {
  /* Demo accounts used to be hidden here. They still take real payments, so
     hiding them meant money could be collected against an account that never
     appeared in the console — flag them instead of filtering them out. */
  const merchants = await store.merchants.all();
  const [allCharges, allPayouts] = await Promise.all([store.charges.all(), store.payouts.all()]);
  const rates = await fx.getRates();
  const toGhs = (amount, currency) => fx.toGhsMinor(amount, currency, rates);
  const midnight = new Date(); midnight.setHours(0, 0, 0, 0);
  const todayStart = midnight.getTime();
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
    /* liveCollected is what the merchant still holds — gross less payouts
       already completed. That is the only figure the console had, so there was
       no way to see what a merchant had actually earned: a merchant paid out
       in full showed zero. Return the gross and the payout total alongside it. */
    const liveGross = liveOk.reduce((s, c) => s + toGhs(c.amount, c.currency), 0);
    const testGross = testOk.reduce((s, c) => s + toGhs(c.amount, c.currency), 0);

    /* Today's live take for this merchant, dated by paidAt like every other
       revenue figure — a charge raised yesterday and approved this morning
       belongs to today. */
    const liveTodayList = liveOk.filter((c) => (c.paidAt || c.createdAt) >= todayStart);
    const liveToday = liveTodayList.reduce((s, c) => s + toGhs(c.amount, c.currency), 0);

    return {
      id: m.id,
      businessName: m.businessName,
      email: m.email,
      websiteUrl: m.websiteUrl || null,
      createdAt: m.createdAt,
      locked: !!m.locked,
      lockReason: m.lockReason || null,
      lockedAt: m.lockedAt || null,
      demo: !!m.demo,
      feeBps: fees.feeBpsForMerchant(m),
      feeBpsCustom: !(m.feeBps === null || m.feeBps === undefined || m.feeBps === ''),
      /* Who set this rate and when. A rate is money, and a figure nobody can
         account for is worse than no figure at all. */
      feeRateSetAt: m.feeRateSetAt || null,
      feeRateSetBy: m.feeRateSetBy || null,
      liveGross,
      liveToday,
      liveTodayCount: liveTodayList.length,
      testGross,
      livePaidOut,
      testPaidOut,
      liveCollected: Math.max(0, liveGross - livePaidOut),
      testCollected: Math.max(0, testGross - testPaidOut),
      totalTransactions: charges.length,
      liveTransactions: charges.filter((c) => (c.mode || 'test') === 'live').length,
      liveSuccessful: liveOk.length,
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

/* Permanently removes a merchant and everything belonging to them.

   Two guards, because this is irreversible and there is no backup to restore
   from. The business name must be echoed back exactly, so it cannot be fired
   by a stray request or a misplaced click. And a merchant still holding funds
   is refused outright — deleting an account you owe money to loses both the
   debt and the record of it. `force` exists for the case where that balance is
   known to be wrong, and is logged when used. */
/* ═══════════════════════ Support conversations ═══════════════════════════
   One thread per merchant. Reads stay open to deactivated merchants — being
   able to ask why is exactly when support matters most — so requireActive is
   not applied here. */

const MAX_SUPPORT_LEN = 4000;

function supportMessage({ merchantId, from, body, authorEmail }) {
  return {
    id: genId('sup_'),
    merchantId,
    from,                         // 'merchant' | 'admin'
    authorEmail: authorEmail || null,
    body: String(body).trim().slice(0, MAX_SUPPORT_LEN),
    createdAt: Date.now(),
    readAt: null,
  };
}

/* ── merchant ── */
router.get('/support', requireAuth, ah(async (req, res) => {
  const messages = await store.support.forMerchant(req.merchant.id);
  await store.support.markRead(req.merchant.id, 'admin', Date.now());
  res.json({ messages });
}));

router.post('/support', supportLimiter, requireAuth, ah(async (req, res) => {
  const body = String((req.body && req.body.body) || '').trim();
  if (!body) { const e = new Error('Type a message first.'); e.status = 400; throw e; }

  const msg = await store.support.insert(supportMessage({
    merchantId: req.merchant.id, from: 'merchant', body, authorEmail: req.merchant.email,
  }));

  /* Tell the admins, or a question sits unread until someone happens to open
     the console. Only on the first unanswered message, so a merchant typing
     several lines does not send several emails. */
  const thread = await store.support.forMerchant(req.merchant.id);
  const priorUnanswered = thread.filter((m) => m.from === 'merchant' && m.id !== msg.id && !m.readAt).length;
  if (!priorUnanswered) {
    const toList = await adminEmails();
    if (toList.length) {
      sendSupportMessageAlert(toList, {
        merchantName: req.merchant.businessName,
        merchantEmail: req.merchant.email,
        body: msg.body,
      }).catch((err) => console.warn('[support-alert]', err.message));
    }
  }
  res.status(201).json({ message: msg });
}));

/* Clearing removes the thread for both sides — there is one conversation, not
   a copy each. Both UIs say so before asking for confirmation. */
router.delete('/support', writeLimiter, requireAuth, ah(async (req, res) => {
  const before = (await store.support.forMerchant(req.merchant.id)).length;
  await store.support.clearForMerchant(req.merchant.id);
  res.json({ ok: true, cleared: before });
}));

/* ── admin ── */
router.get('/admin/support', requireAdminAuth, ah(async (req, res) => {
  const [all, merchants] = await Promise.all([store.support.all(), store.merchants.all()]);
  const byId = Object.fromEntries(merchants.map((m) => [m.id, m]));
  const threads = {};
  for (const m of all) {
    const t = threads[m.merchantId] || (threads[m.merchantId] = {
      merchantId: m.merchantId,
      businessName: (byId[m.merchantId] || {}).businessName || 'Deleted merchant',
      email: (byId[m.merchantId] || {}).email || null,
      messages: 0, unread: 0, lastAt: 0, lastFrom: null, lastBody: '',
    });
    t.messages += 1;
    if (m.from === 'merchant' && !m.readAt) t.unread += 1;
    if (m.createdAt >= t.lastAt) { t.lastAt = m.createdAt; t.lastFrom = m.from; t.lastBody = m.body; }
  }
  /* Unanswered first, then most recent — the queue an admin works through. */
  const list = Object.values(threads).sort((a, b) => (b.unread - a.unread) || (b.lastAt - a.lastAt));
  res.json({ threads: list, totalUnread: list.reduce((s, t) => s + t.unread, 0) });
}));

router.get('/admin/support/:merchantId', requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  const messages = await store.support.forMerchant(req.params.merchantId);
  await store.support.markRead(req.params.merchantId, 'merchant', Date.now());
  res.json({
    messages,
    merchant: merchant ? { id: merchant.id, businessName: merchant.businessName, email: merchant.email, locked: !!merchant.locked } : null,
  });
}));

router.delete('/admin/support/:merchantId', writeLimiter, requireAdminAuth, ah(async (req, res) => {
  const before = (await store.support.forMerchant(req.params.merchantId)).length;
  await store.support.clearForMerchant(req.params.merchantId);
  console.warn(`[admin] ${req.adminEmail} cleared the support thread for ${req.params.merchantId} (${before} messages)`);
  res.json({ ok: true, cleared: before });
}));

router.post('/admin/support/:merchantId', writeLimiter, requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  if (!merchant) { const e = new Error('Merchant not found.'); e.status = 404; throw e; }
  const body = String((req.body && req.body.body) || '').trim();
  if (!body) { const e = new Error('Type a reply first.'); e.status = 400; throw e; }

  const msg = await store.support.insert(supportMessage({
    merchantId: merchant.id, from: 'admin', body, authorEmail: req.adminEmail,
  }));
  if (merchant.email) {
    sendSupportReplyNotice(merchant.email, {
      businessName: merchant.businessName, body: msg.body,
    }).catch((err) => console.warn('[support-reply-notice]', err.message));
  }
  res.status(201).json({ message: msg });
}));

router.delete('/admin/members/:merchantId', writeLimiter, requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  if (!merchant) { const e = new Error('Merchant not found.'); e.status = 404; throw e; }

  const confirm = String((req.body && req.body.confirm) || req.query.confirm || '').trim();
  if (confirm !== String(merchant.businessName || '').trim()) {
    const e = new Error('Type the exact business name to confirm deletion.'); e.status = 400; throw e;
  }

  const [charges, payouts, rates] = await Promise.all([
    store.charges.forMerchant(merchant.id),
    store.payouts.forMerchant(merchant.id),
    fx.getRates(),
  ]);
  const liveGross = charges
    .filter((c) => c.status === 'success' && (c.mode || 'test') === 'live')
    .reduce((s, c) => s + fx.toGhsMinor(c.amount, c.currency, rates), 0);
  const livePaidOut = payouts
    .filter((p) => p.status === 'completed' && (p.mode || 'test') === 'live')
    .reduce((s, p) => s + p.amount, 0);
  const held = Math.max(0, liveGross - livePaidOut);

  const force = String((req.body && req.body.force) || req.query.force || '') === 'true';
  if (held > 0 && !force) {
    const e = new Error(
      `This merchant still holds GHS ${(held / 100).toFixed(2)}. Pay it out first, or deactivate the account instead of deleting it.`,
    );
    e.status = 409; throw e;
  }
  if (held > 0 && force) {
    console.warn(`[admin] ${req.adminEmail} force-deleted ${merchant.id} (${merchant.businessName}) holding GHS ${(held / 100).toFixed(2)}`);
  }

  /* Records go before the merchant: if this fails half-way the merchant row
     survives, so the orphans stay reachable rather than becoming invisible. */
  await store.charges.clearForMerchant(merchant.id);
  await store.events.clearForMerchant(merchant.id);
  await store.payouts.clearForMerchant(merchant.id);
  await store.support.clearForMerchant(merchant.id);
  await store.merchants.del(merchant.id);

  console.warn(`[admin] ${req.adminEmail} deleted merchant ${merchant.id} (${merchant.businessName}) — ${charges.length} charges, ${payouts.length} payouts`);
  res.json({
    ok: true,
    deleted: { merchantId: merchant.id, businessName: merchant.businessName, charges: charges.length, payouts: payouts.length },
  });
}));

/* ═══════════════════════ Partners ═══════════════════════════════════════
   People who bring deposits to a merchant and take a share of what they bring.
   Managed by an admin, because the commission is money leaving the merchant
   and should not be self-serve.

   Revenue is counted from successful live deposits only, matching every other
   revenue figure in the console — a pending deposit has not been paid and is
   reported separately so it is visible without being counted. */

async function partnerReport(merchant) {
  const charges = await store.charges.forMerchant(merchant.id);
  const midnight = new Date(); midnight.setHours(0, 0, 0, 0);
  const todayStart = midnight.getTime();
  const live = charges.filter((c) => (c.mode || 'test') === 'live');

  const rows = partners.list(merchant).map((p) => {
    const mine = live.filter((c) => c.partnerId === p.id);
    const paid = mine.filter((c) => c.status === 'success');
    const today = paid.filter((c) => (c.paidAt || c.createdAt) >= todayStart);

    /* Seven separate days, newest first — the same shape the revenue panel
       uses, so a partner's week reads the same way as the platform's. */
    const byDay = [];
    for (let i = 0; i < 7; i++) {
      const dd = new Date(); dd.setHours(0, 0, 0, 0); dd.setDate(dd.getDate() - i);
      const start = dd.getTime();
      const inDay = paid.filter((c) => {
        const at = c.paidAt || c.createdAt;
        return at >= start && at < start + 86_400_000;
      });
      byDay.push({
        date: dd.toISOString().slice(0, 10),
        label: dd.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' }),
        volume: inDay.reduce((s, c) => s + (c.amount || 0), 0),
        commission: inDay.reduce((s, c) => s + (c.partnerCommission || 0), 0),
        count: inDay.length,
      });
    }

    return {
      ...p,
      userIdCount: partners.userIds(p).length,
      deposits: paid.length,
      volume: paid.reduce((s, c) => s + (c.amount || 0), 0),
      commission: paid.reduce((s, c) => s + (c.partnerCommission || 0), 0),
      todayVolume: today.reduce((s, c) => s + (c.amount || 0), 0),
      todayCommission: today.reduce((s, c) => s + (c.partnerCommission || 0), 0),
      todayDeposits: today.length,
      pending: mine.filter((c) => c.status === 'pending').length,
      lastDepositAt: paid.length ? Math.max(...paid.map((c) => c.paidAt || c.createdAt)) : null,
      byDay,
    };
  });

  /* Deposits that arrived carrying a code nobody recognises. Silent otherwise,
     and silence here means somebody is not being paid. */
  const unknown = {};
  live.filter((c) => c.partnerCodeUnknown && c.status === 'success')
    .forEach((c) => { unknown[c.partnerCodeUnknown] = (unknown[c.partnerCodeUnknown] || 0) + 1; });

  return {
    partners: rows.sort((a, b) => b.commission - a.commission),
    unknownCodes: Object.entries(unknown).map(([code, count]) => ({ code, count })),
    unattributed: live.filter((c) => c.status === 'success' && !c.partnerId).length,
  };
}

/* The list of the merchant's own user ids belonging to this partner. Sent as
   a pasted block or an array; whitespace, commas and newlines all separate. */
router.put('/admin/members/:merchantId/partners/:partnerId/users', writeLimiter, requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  if (!merchant) { const e = new Error('Merchant not found.'); e.status = 404; throw e; }
  const partner = partners.byId(merchant, req.params.partnerId);
  if (!partner) { const e = new Error('Partner not found.'); e.status = 404; throw e; }

  const ids = partners.parseUserIds((req.body && (req.body.userIds ?? req.body.text)) || '');

  /* One user cannot belong to two partners — that would credit the same
     deposit twice depending on which was found first. */
  const clash = [];
  for (const other of partners.list(merchant)) {
    if (other.id === partner.id) continue;
    const overlap = ids.filter((x) => partners.userIds(other).includes(x));
    if (overlap.length) clash.push({ partner: other.name, count: overlap.length, sample: overlap.slice(0, 3) });
  }
  if (clash.length) {
    const e = new Error(`Some of those users are already assigned to ${clash.map((c) => `${c.partner} (${c.count})`).join(', ')}. Remove them there first.`);
    e.status = 409; throw e;
  }

  partner.userIds = ids;
  merchant.partners = partners.list(merchant).map((x) => (x.id === partner.id ? partner : x));
  await store.merchants.update(merchant);
  res.json(await partnerReport(merchant));
}));

/* Credits deposits already taken.

   Only settled deposits are touched: a pending one still has the checkout and
   the gateway callback writing to it, and a bulk write would race them.

   These deposits were taken before anyone was assigned to them, so there is no
   historical rate to honour — they are credited at the partner's rate as it
   stands now. That is a decision with money attached, so the response says
   exactly how many were changed and at what rate. */
router.post('/admin/members/:merchantId/partners/backfill', writeLimiter, requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  if (!merchant) { const e = new Error('Merchant not found.'); e.status = 404; throw e; }

  const charges = await store.charges.forMerchant(merchant.id);
  const settled = charges.filter((c) => (c.mode || 'test') === 'live'
    && (c.status === 'success' || c.status === 'failed')
    && !c.partnerId);

  const dryRun = !(req.body && req.body.confirm === true);
  const perPartner = {};
  let changed = 0;

  for (const c of settled) {
    const partner = partners.byUserId(merchant, partners.userIdOf(c));
    if (!partner) continue;
    const row = perPartner[partner.id] || (perPartner[partner.id] = {
      name: partner.name, rate: partner.commissionBps, paid: 0, failed: 0, volume: 0, commission: 0,
    });
    /* Paid and failed are counted apart. Both get the partner's name attached
       so the record is complete, but only a paid one earns anything, and a
       confirmation that lumps them together overstates what is being agreed. */
    if (c.status === 'success') {
      row.paid++;
      row.volume += c.amount || 0;
      row.commission += partners.commissionFor(c.amount, partner.commissionBps);
    } else {
      row.failed++;
    }
    if (!dryRun) {
      partners.attach(c, partner);
      c.backfilledAt = Date.now();
      /* forceUpdate, not update: these are settled records with no other
         writer, and a version conflict here would silently skip a deposit. */
      await store.charges.forceUpdate(c);
      changed++;
    }
  }

  res.json({
    dryRun,
    candidates: settled.length,
    matched: Object.values(perPartner).reduce((s, r) => s + r.paid + r.failed, 0),
    matchedPaid: Object.values(perPartner).reduce((s, r) => s + r.paid, 0),
    changed,
    perPartner: Object.values(perPartner),
    report: dryRun ? null : await partnerReport(merchant),
  });
}));

router.get('/admin/members/:merchantId/partners', requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  if (!merchant) { const e = new Error('Merchant not found.'); e.status = 404; throw e; }
  res.json(await partnerReport(merchant));
}));

router.post('/admin/members/:merchantId/partners', writeLimiter, requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  if (!merchant) { const e = new Error('Merchant not found.'); e.status = 404; throw e; }

  const name = String((req.body && req.body.name) || '').trim().slice(0, 80);
  if (name.length < 2) { const e = new Error('Give the partner a name.'); e.status = 400; throw e; }

  const bps = Number(req.body && req.body.commissionBps);
  if (!Number.isFinite(bps) || bps < 0 || bps > partners.MAX_COMMISSION_BPS) {
    const e = new Error('Commission must be between 0% and 50%.'); e.status = 400; throw e;
  }

  /* Codes are unique across every merchant: a hosted link carries nothing but
     the code, so a clash would send deposits to the wrong business. */
  const all = await store.merchants.all();
  const code = partners.uniqueCode(all, req.body && req.body.code, name);

  merchant.partners = partners.list(merchant).concat([{
    id: genId('ptr_'),
    name,
    code,
    commissionBps: Math.round(bps),
    active: true,
    createdAt: Date.now(),
    createdBy: req.adminEmail || null,
  }]);
  await store.merchants.update(merchant);
  res.status(201).json(await partnerReport(merchant));
}));

router.put('/admin/members/:merchantId/partners/:partnerId', writeLimiter, requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  if (!merchant) { const e = new Error('Merchant not found.'); e.status = 404; throw e; }
  const partner = partners.byId(merchant, req.params.partnerId);
  if (!partner) { const e = new Error('Partner not found.'); e.status = 404; throw e; }

  const b = req.body || {};
  if (b.name !== undefined) {
    const name = String(b.name).trim().slice(0, 80);
    if (name.length < 2) { const e = new Error('Give the partner a name.'); e.status = 400; throw e; }
    partner.name = name;
  }
  if (b.commissionBps !== undefined) {
    const bps = Number(b.commissionBps);
    if (!Number.isFinite(bps) || bps < 0 || bps > partners.MAX_COMMISSION_BPS) {
      const e = new Error('Commission must be between 0% and 50%.'); e.status = 400; throw e;
    }
    /* Only deposits from here on use the new rate. Every deposit already
       carries the rate it was taken at, so nothing already earned moves. */
    partner.commissionBps = Math.round(bps);
  }
  if (b.active !== undefined) partner.active = Boolean(b.active);

  merchant.partners = partners.list(merchant).map((x) => (x.id === partner.id ? partner : x));
  await store.merchants.update(merchant);
  res.json(await partnerReport(merchant));
}));

/* Removing a partner does not touch their deposits: those are the merchant's
   revenue and stay exactly where they are. What is lost is the link and any
   further attribution, which is why the deposits already recorded keep the
   partner's name on them. */
router.delete('/admin/members/:merchantId/partners/:partnerId', writeLimiter, requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  if (!merchant) { const e = new Error('Merchant not found.'); e.status = 404; throw e; }
  merchant.partners = partners.list(merchant).filter((p) => p.id !== req.params.partnerId);
  await store.merchants.update(merchant);
  res.json(await partnerReport(merchant));
}));

/* Sets one merchant's fee rate, or clears it back to the platform default.

   Rate is in basis points so it stays exact — 300 is 3%, 250 is 2.5%. Only
   charges raised after the change use it: each charge records the rate it was
   priced at, so re-rating a merchant never rewrites what they have already
   been billed. */
router.put('/admin/members/:merchantId/fee', writeLimiter, requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  if (!merchant) { const e = new Error('Merchant not found.'); e.status = 404; throw e; }

  const raw = req.body && req.body.feeBps;
  /* null / '' clears the override and puts them back on the platform rate. */
  if (raw === null || raw === undefined || raw === '') {
    delete merchant.feeBps;
  } else {
    const bps = Number(raw);
    if (!Number.isFinite(bps) || bps < 0 || bps > 2000) {
      const e = new Error('Rate must be between 0% and 20%.'); e.status = 400; throw e;
    }
    merchant.feeBps = Math.round(bps);
  }
  merchant.feeRateSetAt = Date.now();
  merchant.feeRateSetBy = req.adminEmail || null;
  await store.merchants.update(merchant);

  res.json({
    ok: true,
    merchantId: merchant.id,
    feeBps: fees.feeBpsForMerchant(merchant),
    feeBpsCustom: merchant.feeBps !== undefined,
  });
}));

router.post('/admin/members/:merchantId/lock', writeLimiter, requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  if (!merchant) { const e = new Error('Merchant not found.'); e.status = 404; throw e; }
  const locking = !!(req.body && req.body.locked);
  if (locking) {
    /* A reason is required: the merchant is shown it verbatim when they sign
       in, and "your account has been deactivated" with no explanation is what
       this change exists to stop. */
    const reason = String((req.body && req.body.reason) || '').trim();
    if (reason.length < 5) {
      const e = new Error('A reason is required when deactivating an account.'); e.status = 400; throw e;
    }
    merchant.lockReason = reason.slice(0, 300);
    merchant.lockedAt = Date.now();
    merchant.lockedBy = req.adminEmail || null;
  } else {
    delete merchant.lockReason;
    delete merchant.lockedAt;
    delete merchant.lockedBy;
  }
  merchant.locked = locking;
  await store.merchants.update(merchant);
  res.json({ ok: true, merchantId: merchant.id, locked: merchant.locked, lockReason: merchant.lockReason || null });
}));

router.delete('/admin/transactions', writeLimiter, requireAdminAuth, ah(async (req, res) => {
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

router.post('/admin/payouts', writeLimiter, requireAdminAuth, ah(async (req, res) => {
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

router.post('/admin/payouts/:id/complete', writeLimiter, requireAdminAuth, ah(async (req, res) => {
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

router.post('/payouts', writeLimiter, requireAuth, requireActive, ah(async (req, res) => {
  const { amount, method, bank, accountNumber, accountName, mobileProvider, mobileNumber, note } = req.body || {};

  /* Validate before rounding: Math.round(Infinity) is Infinity, which passes a
     bare `<= 0` test and is then serialised to null. */
  const rawAmt = Number(amount);
  if (!Number.isFinite(rawAmt) || rawAmt <= 0 || rawAmt > MAX_AMOUNT_MINOR) {
    const e = new Error('Enter a valid amount.'); e.status = 400; throw e;
  }
  const amt = Math.round(rawAmt);

  /* A payout was only checked for being positive — a merchant could request
     any sum regardless of what they had actually collected, and the request
     would sit in the admin queue looking exactly like a legitimate one. Cap it
     at what is genuinely available: settled live revenue, less payouts already
     completed, less anything already awaiting approval. */
  const [ownCharges, ownPayouts, payoutRates] = await Promise.all([
    store.charges.forMerchant(req.merchant.id),
    store.payouts.forMerchant(req.merchant.id),
    fx.getRates(),
  ]);
  const liveGross = ownCharges
    .filter((c) => c.status === 'success' && (c.mode || 'test') === 'live')
    .reduce((sum, c) => sum + fx.toGhsMinor(c.amount, c.currency, payoutRates), 0);
  const alreadyOut = ownPayouts
    .filter((pp) => ['completed', 'pending', 'processing'].includes(pp.status) && (pp.mode || 'test') === 'live')
    .reduce((sum, pp) => sum + pp.amount, 0);
  const availableToPayOut = Math.max(0, liveGross - alreadyOut);

  if (amt > availableToPayOut) {
    const e = new Error(
      `You can request up to GHS ${(availableToPayOut / 100).toFixed(2)}. That is your collected balance less payouts already completed or awaiting approval.`,
    );
    e.status = 400; throw e;
  }
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

  /* A payout sits at 'pending' until an admin actions it, so nobody finds out
     it was requested unless they happen to open the console. Notify the admins
     as soon as it is raised. Not awaited: a mail problem must not fail the
     request, which is already recorded. */
  const toList = await adminEmails();
  if (toList.length) {
    const destination = payout.method === 'mobile_money'
      ? [payout.mobileProvider, payout.mobileNumber].filter(Boolean).join(' · ')
      : [payout.bank, payout.accountNumber, payout.accountName && `(${payout.accountName})`].filter(Boolean).join(' · ');
    sendPayoutRequestAlert(toList, {
      payoutId: payout.id,
      amount: payout.amount,
      currency: payout.currency || 'GHS',
      merchantName: req.merchant.businessName,
      method: payout.method,
      destination,
      note: payout.note,
      mode: payout.mode,
    }).catch(err => console.warn('[payout-request-alert]', err.message));
  }

  res.status(201).json({ payout });
}));

router.get('/admin/settlements', requireAdminAuth, ah(async (req, res) => {
  res.json({ settlements: await store.settlements.all() });
}));

router.post('/admin/settlements', writeLimiter, requireAdminAuth, ah(async (req, res) => {
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

router.post('/admin/new-payment', writeLimiter, requireAdminAuth, ah(async (req, res) => {
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

router.put('/admin/bank-accounts', writeLimiter, requireAdminAuth, ah(async (req, res) => {
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
router.post('/charges/:reference/notify-transfer', payLimiter, loadCharge, ah(async (req, res) => {
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

router.post('/admin/charges/:reference/mark-paid', writeLimiter, requireAdminAuth, ah(async (req, res) => {
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

    /* The merchant is the one who has actually been paid, so they get their
       own notice. Sent separately from the admin alert rather than as an extra
       recipient: different wording, and it links to their dashboard, not the
       admin console. Failure is logged, never allowed to affect the charge. */
    if (merchant.email) {
      sendMerchantDepositNotice(merchant.email, {
        reference: charge.reference,
        amount: charge.amount,
        currency: charge.currency || 'GHS',
        businessName: merchant.businessName,
        payerName: charge.payerName,
        method: charge.method,
      }).catch(err => console.warn('[merchant-deposit-notice]', err.message));
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

/* MCASH's mirror of applyNalopayStatus. Same rules: terminal states are
   final, unknown statuses stay pending, and everything the IPN reported is
   kept on the charge for diagnosis. */
function applyMcashStatus(charge, mcashStatus, extra = {}) {
  const mapped = mcash.mapStatus(mcashStatus);
  const now = Date.now();

  if (extra.raw) {
    charge.mcash = {
      status: mcashStatus,
      transactionId: extra.raw.payment_trx_id || extra.raw.transaction_id || null,
      charges: extra.raw.charge || extra.raw.charges,
      reportedAmount: extra.raw.amount,
      reportedCurrency: extra.raw.currency,
      observedAt: now,
    };
  }

  if (charge.status === 'success' || charge.status === 'failed') {
    return { next: charge.status };
  }

  if (mapped === 'success') {
    charge.status = 'success';
    charge.paidAt = now;
    charge.updatedAt = now;
    charge.resolvedInMs = charge.createdAt ? now - charge.createdAt : null;
    charge.auth = Object.assign({ provider: 'mcash' }, charge.auth, extra.auth);
  } else if (mapped === 'failed') {
    charge.status = 'failed';
    charge.updatedAt = now;
    charge.resolvedInMs = charge.createdAt ? now - charge.createdAt : null;
    charge.failure = { message: extra.message || 'Payment failed', mcashStatus };
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

/* MCASH is hosted-checkout only: mobile money and card are both completed on
   MCASH's own page, so every method resolves to a redirect. Settlement then
   arrives via the signed IPN — there is nothing to poll. */
async function payWithMcash(req, res) {
  const charge = req.charge;
  const mode = (charge.mode || 'test') === 'live' ? 'live' : 'test';

  const { method, payerName } = req.body || {};
  if (payerName && String(payerName).trim()) { charge.payerName = String(payerName).trim(); }
  if (method !== 'mobile_money' && method !== 'card') {
    const e = new Error('MCASH supports mobile money and card payments only.');
    e.status = 400; throw e;
  }

  /* With API keys the hosted checkout is used; without them, live payments
     fall back to the static pay-link. */
  const useApi = mode === 'test' ? mcash.sandboxConfigured() : mcash.configured();
  if (!useApi) {
    if (mode === 'test') {
      const e = new Error(
        'Test mode is not available — payments are completed on the MCASH pay link, which moves real money. Use your live API key (pk_live_…), or set MCASH_TEST_PUBLIC_KEY / MCASH_TEST_SECRET_KEY sandbox keys.',
      );
      e.status = 400; throw e;
    }
    if (!mcash.paylinkUrl()) {
      const e = new Error('MCASH is not configured.'); e.status = 503; throw e;
    }
    /* Pay-link flow: the payer types the amount on MCASH's fixed page and
       nothing comes back to us, so there is NOTHING to settle against. The
       charge stays pending; the payer's "I've paid" only emails the admins
       (notify-transfer), and settlement happens exclusively through the
       admin console's mark-paid after checking the MCASH account — the same
       trust model as the static bank-transfer method. */
    /* Amount fingerprint. The IPN for a pay-link payment carries nothing that
       ties it to a charge except the amount, so the amount must identify the
       charge uniquely. When another open pay-link charge already expects the
       same figure, this payer is asked for a few pesewas more (20.01, 20.02…)
       — the surcharge is at most GHS 0.99 and makes auto-confirmation
       unambiguous. A repeat attempt keeps its fingerprint so the payer never
       sees the figure change between retries. */
    const payable = fees.payableAmount(charge);
    const open = (await store.charges.pendingPaylink()).filter((c) => c.reference !== charge.reference);
    const taken = new Set(open.map((c) => c.mcashPayAmount || fees.payableAmount(c)));
    let payAmount = (charge.mcashPayAmount && !taken.has(charge.mcashPayAmount)) ? charge.mcashPayAmount : payable;
    if (taken.has(payAmount)) {
      for (let delta = 1; delta <= 99; delta++) {
        if (!taken.has(payable + delta)) { payAmount = payable + delta; break; }
      }
    }

    await saveChargeWithRetry(charge, (c) => {
      c.method = method;
      c.mcashPaylink = true;
      c.mcashPayAmount = payAmount;
      c.attemptCount = (c.attemptCount || 0) + 1;
      c.lastAttemptAt = Date.now();
      c.updatedAt = Date.now();
      c.auth = { provider: 'mcash', channel: 'paylink' };
    });
    return res.json({
      charge,
      next: 'paylink',
      detail: {
        url: mcash.paylinkUrl(),
        amountMajor: mcash.toMajor(payAmount),
        currency: charge.currency || 'GHS',
        reference: charge.reference,
      },
    });
  }

  /* Fresh identifier per attempt, like the Nalopay attemptRef — the IPN echoes
     it back and byMcashRef() maps it to this charge. It also goes into the
     IPN's HMAC, so it must be sent verbatim. */
  const attemptRef = `cwr_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  const returnUrl = `${originOf(req)}/checkout?reference=${encodeURIComponent(charge.reference)}`;

  const data = await mcash.initiate({
    mode,
    identifier: attemptRef,
    /* The payer is charged the total — the merchant's amount plus the
       platform fee. charge.amount stays what the merchant receives. */
    amountMinor: fees.payableAmount(charge),
    currency: charge.currency || 'GHS',
    details: `KassifyPay ${charge.reference}`,
    customerName: charge.payerName || 'Customer',
    /* customer_email is required by MCASH; most checkout links carry none. */
    customerEmail: charge.customerEmail || 'payments@kassifypay.com',
    ipnUrl: `${originOf(req)}/api/webhooks/mcash`,
    successUrl: returnUrl,
    cancelUrl: returnUrl,
  });
  console.log('[MCASH /initiate]', JSON.stringify({ ok: data.success === 'ok', http: data.httpStatus, mode }));
  if (data.success !== 'ok' || !data.url) {
    const msg = (data.error && (data.error.message || data.error)) || data.message || 'Could not start the payment session.';
    throw Object.assign(new Error(typeof msg === 'string' ? msg : 'Could not start the payment session.'), { status: 400 });
  }

  await saveChargeWithRetry(charge, (c) => {
    c.method = method;
    c.mcashRef = attemptRef;
    c.mcashMode = mode;
    c.attemptCount = (c.attemptCount || 0) + 1;
    c.lastAttemptAt = Date.now();
    c.updatedAt = Date.now();
    c.auth = { provider: 'mcash', channel: method === 'card' ? 'card' : 'mobile_money' };
  });
  return res.json({ charge, next: 'redirect', detail: data.url });
}

router.post('/charges/:reference/pay', payLimiter, loadCharge, ah(async (req, res) => {
  const charge = req.charge;
  if (charge.status === 'success' || charge.status === 'failed') return res.json({ charge, next: charge.status });

  if ((await activeProvider()) === 'mcash') return payWithMcash(req, res);

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
      /* The payer is charged the total — the merchant's amount plus the
         platform fee. charge.amount stays what the merchant receives. */
      amountMinor: fees.payableAmount(charge),
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
      /* Nalopay sometimes hands back a USSD string the payer can dial to
         approve. It was being returned and dropped on the floor, which is
         exactly what a payer whose prompt never arrived needs. Kept on the
         charge so it survives a page reload too. */
      if (data.data.otp_code) c.ussdCode = String(data.data.otp_code);
    });
    /* Always PENDING here — the payer approves the prompt on their handset and
       the checkout polls. `otp_code` is a USSD string to dial, not an OTP. */
    return res.json({ charge, next: 'pending', detail: data.data.otp_code || null, ussdCode: data.data.otp_code || null });
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
        price: nalopay.toMajor(fees.payableAmount(charge)),
        /* Only path back to our charge — checkout callbacks echo the summary,
           not the arbitrary extra_data that collections return. */
        metadata: { cowrie_reference: charge.reference },
      }],
      itemCount: 1,
      totalMinor: fees.payableAmount(charge),
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

/* A pay-link IPN can land before its charge is flagged, or while a stale
   same-amount charge was still open. The checkout polls while the payer is on
   the waiting screen, so every poll retries the match — under exactly the
   webhook's uniqueness rules, in both directions: one unclaimed payment for
   the amount, and one open charge expecting it. */
async function settleFromRecordedIpns(charge) {
  const expect = charge.mcashPayAmount || fees.payableAmount(charge);
  const list = (await store.settings.get('mcash_ipns')) || [];
  const matches = list.filter((p) => p.verified && !p.matchedReference &&
    mcash.mapStatus(p.status) === 'success' && mcash.toMinor(p.amount) === expect);
  /* A payment whose payload names this very charge needs no uniqueness — the
     reference plus the amount already identify it. */
  let rec = matches.find((p) => p.chargeRefHint === charge.reference) || null;
  if (!rec) {
    const contenders = (await store.charges.pendingPaylink())
      .filter((c) => (c.mcashPayAmount || fees.payableAmount(c)) === expect);
    /* Same recency tie-break as the webhook: this charge wins if it is the
       only contender, or the only one with a fresh attempt. */
    let mine = contenders.length === 1 && contenders[0].reference === charge.reference;
    if (!mine && contenders.length > 1) {
      const fresh = contenders.filter((c) => Date.now() - (c.lastAttemptAt || 0) <= 30 * 60_000);
      mine = fresh.length === 1 && fresh[0].reference === charge.reference;
    }
    if (!mine) return;
    /* Any of the unclaimed same-amount payments is a genuine payment of the
       right figure, so which record gets consumed doesn't matter — take the
       newest fresh one. */
    rec = matches.length === 1 ? matches[0]
      : matches.filter((p) => Date.now() - p.at <= 30 * 60_000).sort((a, b) => b.at - a.at)[0];
    if (!rec) return;
  }
  await saveChargeWithRetry(charge, (c) => applyMcashStatus(c, rec.status, {
    raw: { amount: rec.amount, currency: rec.currency, payment_trx_id: rec.transactionId },
  }));
  await emitWebhookIfTerminal(charge);
  if (charge.status === 'success') {
    rec.matchedReference = charge.reference;
    rec.autoSettled = true;
    await store.settings.set('mcash_ipns', list);
  }
}

router.get('/charges/:reference/poll', payLimiter, loadCharge, ah(async (req, res) => {
  const charge = req.charge;
  if (charge.status === 'success' || charge.status === 'failed') return res.json({ charge, next: charge.status });
  if (charge.mcashPaylink) {
    await settleFromRecordedIpns(charge);
    return res.json({ charge, next: charge.status === 'pending' ? 'pending' : charge.status });
  }
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
router.post('/webhooks/nalopay', webhookLimiter, ah(async (req, res) => {
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

/* MCASH IPN — the ONLY settlement path for MCASH charges (there is no
   status-lookup endpoint to re-check against). It is trusted solely because
   of its HMAC: signature = HMAC-SHA256(amount + identifier, secret key),
   uppercase hex, which a forger cannot produce without the secret. The amount
   is additionally checked against our own record so even a validly-signed IPN
   can never settle a charge for less than the payer owed. */
/* Every notification is kept (newest first, capped) so money arriving at
   MCASH is visible in the admin console — before this, a payment's only
   trace was a line in the Render logs. */
async function recordMcashIpn(record) {
  try {
    const list = (await store.settings.get('mcash_ipns')) || [];
    list.unshift(record);
    await store.settings.set('mcash_ipns', list.slice(0, 200));
  } catch (e) { console.warn('[MCASH IPN] could not record:', e.message); }
}

/* A cwr_ reference the payer carried through a note/description field —
   scanned across the whole payload, since MCASH does not document what its
   pay-link IPN contains. When present it beats amount matching. */
function chargeRefHintFrom(body) {
  try {
    const m = JSON.stringify(body).match(/cwr_[a-z0-9]{6,}/i);
    return m ? m[0] : null;
  } catch { return null; }
}

router.post('/webhooks/mcash', webhookLimiter, ah(async (req, res) => {
  const body = req.body || {};
  /* PHP-style form arrays: data[amount]=… parses to body.data.amount under
     extended urlencoded parsing; fall back to the flat key just in case. */
  const d = (body.data && typeof body.data === 'object') ? body.data : {};
  const amountRaw = d.amount != null ? String(d.amount) : String(body['data[amount]'] ?? '');
  const identifier = body.identifier != null ? String(body.identifier) : null;
  console.log('[MCASH IPN]', JSON.stringify({ identifier, claimed: body.status }));

  /* The full payload is kept (capped) because MCASH's pay-link IPN format is
     undocumented — the admin console shows it, which is how any field usable
     for matching gets discovered. */
  let raw = null;
  try { raw = JSON.stringify(body).slice(0, 4000); } catch { /* unserialisable */ }

  const record = {
    id: genId('ipn_'),
    at: Date.now(),
    identifier,
    status: body.status != null ? String(body.status) : null,
    amount: amountRaw || null,
    currency: d.currency ? String(d.currency) : null,
    transactionId: d.payment_trx_id || d.transaction_id || null,
    chargeRefHint: chargeRefHintFrom(body),
    raw,
    verified: false,          // HMAC checked out against our secret key
    matchedReference: null,   // the KassifyPay charge this was tied to
    autoSettled: false,       // true when this notification marked it paid
  };

  /* API-mode charges carry the identifier we minted; pay-link payments carry
     MCASH's own, so `charge` stays null for those. */
  let charge = identifier ? await store.charges.byMcashRef(identifier) : null;
  const mode = charge && charge.mcashMode === 'test' ? 'test' : 'live';
  record.verified = Boolean(identifier && body.signature &&
    mcash.verifySignature({ amountRaw, identifier, signature: body.signature, mode }));

  if (charge) {
    record.matchedReference = charge.reference;
    const settled = charge.status === 'success' || charge.status === 'failed';
    if (!record.verified) {
      console.warn('[MCASH IPN] rejected: bad signature', JSON.stringify({ identifier }));
    } else if (!settled && mcash.toMinor(amountRaw) !== fees.payableAmount(charge)) {
      /* The signed amount must be what this charge's payer owed. */
      console.warn('[MCASH IPN] rejected: amount mismatch', JSON.stringify({ identifier, reported: amountRaw, expected: fees.payableAmount(charge) }));
    } else if (!settled) {
      await saveChargeWithRetry(charge, (c) => applyMcashStatus(c, body.status, { raw: d }));
      await emitWebhookIfTerminal(charge);
      record.autoSettled = charge.status === 'success';
    }
  } else if (record.verified && mcash.mapStatus(body.status) === 'success') {
    /* Pay-link payment. Exact reference beats everything: when the payload
       carries a cwr_ reference (the payer pasted it into the note, as the
       checkout asks) naming an open charge whose amount matches, that charge
       settles with no guessing. */
    const hinted = record.chargeRefHint ? await store.charges.byReference(record.chargeRefHint) : null;
    if (hinted && hinted.status !== 'success' && hinted.status !== 'failed' &&
        (hinted.mcashPayAmount || fees.payableAmount(hinted)) === mcash.toMinor(amountRaw)) {
      charge = hinted;
      await saveChargeWithRetry(charge, (c) => applyMcashStatus(c, body.status, { raw: d }));
      await emitWebhookIfTerminal(charge);
      record.matchedReference = charge.reference;
      record.autoSettled = charge.status === 'success';
      await recordMcashIpn(record);
      return res.json({ received: true });
    }
    /* Otherwise settle ONLY when the signed amount matches exactly one recent
       open pay-link charge — ambiguity (two payers owing the same amount)
       always falls through to manual confirmation. Unverified notifications
       never settle anything: the endpoint is public, and an amount is
       trivial to guess. */
    const cutoff = Date.now() - 48 * 3600_000;
    const candidates = (await store.charges.pendingPaylink())
      .filter((c) => (c.lastAttemptAt || c.createdAt || 0) >= cutoff)
      .filter((c) => (c.mcashPayAmount || fees.payableAmount(c)) === mcash.toMinor(amountRaw));
    record.candidates = candidates.length;
    /* Recency tie-break: a notification lands moments after its payer's
       attempt, so when several charges share the amount but only ONE has a
       fresh attempt, the fresh one is the payer — stale test charges must not
       block real money. Two genuinely concurrent same-amount payers both
       look fresh and still fall through to manual confirmation. */
    let pick = candidates.length === 1 ? candidates[0] : null;
    if (!pick && candidates.length > 1) {
      const fresh = candidates.filter((c) => Date.now() - (c.lastAttemptAt || 0) <= 30 * 60_000);
      if (fresh.length === 1) pick = fresh[0];
    }
    if (pick) {
      charge = pick;
      await saveChargeWithRetry(charge, (c) => applyMcashStatus(c, body.status, { raw: d }));
      await emitWebhookIfTerminal(charge);
      record.matchedReference = charge.reference;
      record.autoSettled = charge.status === 'success';
    } else {
      console.log('[MCASH IPN] not auto-confirmed — needs manual match', JSON.stringify({ amount: amountRaw, candidates: candidates.length }));
    }
  }

  await recordMcashIpn(record);
  res.json({ received: true });
}));

router.get('/admin/mcash-payments', requireAdminAuth, ah(async (req, res) => {
  const list = (await store.settings.get('mcash_ipns')) || [];
  /* Records written before ids existed get one on first read, so the apply
     route below can always address them. */
  let changed = false;
  for (const p of list) { if (!p.id) { p.id = genId('ipn_'); changed = true; } }
  if (changed) await store.settings.set('mcash_ipns', list);
  res.json({ payments: list });
}));

/* One-click confirmation from the admin console: applies a recorded MCASH
   payment to a specific charge. Restricted to signature-verified successful
   payments whose amount matches the charge exactly — an admin who wants to
   override those guards can still use the plain mark-paid route. */
router.post('/admin/mcash-payments/:id/apply', writeLimiter, requireAdminAuth, ah(async (req, res) => {
  const list = (await store.settings.get('mcash_ipns')) || [];
  const rec = list.find((p) => p.id === req.params.id);
  if (!rec) { const e = new Error('Payment record not found.'); e.status = 404; throw e; }
  if (!rec.verified || mcash.mapStatus(rec.status) !== 'success') {
    const e = new Error('Only signature-verified successful payments can be applied.'); e.status = 400; throw e;
  }
  if (rec.matchedReference) { const e = new Error('This payment is already applied to a charge.'); e.status = 409; throw e; }

  const charge = await store.charges.byReference(String((req.body || {}).reference || ''));
  if (!charge) { const e = new Error('Charge not found.'); e.status = 404; throw e; }
  if (charge.status === 'success' || charge.status === 'failed') {
    const e = new Error('That charge is already settled.'); e.status = 409; throw e;
  }
  if (mcash.toMinor(rec.amount) !== (charge.mcashPayAmount || fees.payableAmount(charge))) {
    const e = new Error('The payment amount does not match this charge.'); e.status = 400; throw e;
  }

  await saveChargeWithRetry(charge, (c) => applyMcashStatus(c, rec.status, {
    raw: { amount: rec.amount, currency: rec.currency, payment_trx_id: rec.transactionId },
  }));
  await emitWebhookIfTerminal(charge);
  rec.matchedReference = charge.reference;
  rec.appliedAt = Date.now();
  await store.settings.set('mcash_ipns', list);
  res.json({ ok: true, charge: { reference: charge.reference, status: charge.status } });
}));

/* ========================= KYC ========================= */

router.post('/kyc', kycLimiter, requireAuth, requireActive, ah(async (req, res) => {
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

router.post('/admin/kyc/:merchantId/approve', writeLimiter, requireAdminAuth, ah(async (req, res) => {
  const merchant = await store.merchants.byId(req.params.merchantId);
  if (!merchant) { const e = new Error('Merchant not found.'); e.status = 404; throw e; }
  merchant.kycStatus = 'approved';
  merchant.kycReviewedAt = Date.now();
  merchant.kycRejectionReason = null;
  await store.merchants.update(merchant);
  sendKycApproved(merchant.email, merchant.businessName).catch(() => {});
  res.json({ merchant: publicMerchant(merchant) });
}));

router.post('/admin/kyc/:merchantId/reject', writeLimiter, requireAdminAuth, ah(async (req, res) => {
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
  /* MCASH keys come from app.arkmah.com → Developer. test* = sandbox pair,
     live* = live pair. */
  { id: 'mcash',         name: 'MCASH (arkmah.com)', status: 'integrated', website: 'https://app.arkmah.com',       fields: { testPublicKey: 'Sandbox public key',                 testSecretKey: 'Sandbox secret key',                  livePublicKey: 'Live public key',                    liveSecretKey: 'Live secret key' } },
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

/* MCASH uses the four slots as-is; either complete pair is enough (sandbox-
   only is a valid way to trial the integration). Null keeps env vars in
   charge, as with Nalopay. */
function mcashKeysFrom(g) {
  if (!g) return null;
  const livePair = g.livePublicKey && g.liveSecretKey;
  const testPair = g.testPublicKey && g.testSecretKey;
  if (!livePair && !testPair) return null;
  return {
    livePublicKey: g.livePublicKey || '',
    liveSecretKey: g.liveSecretKey || '',
    testPublicKey: g.testPublicKey || '',
    testSecretKey: g.testSecretKey || '',
  };
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

router.put('/admin/gateways/:id', writeLimiter, requireAdminAuth, ah(async (req, res) => {
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
  if (id === 'mcash') mcash.configureKeys(mcashKeysFrom(gs.gateways.mcash));
  res.json({ ok: true });
}));

router.put('/admin/gateways/:id/toggle', writeLimiter, requireAdminAuth, ah(async (req, res) => {
  const { id } = req.params;
  if (!SUPPORTED_GATEWAYS.find(g => g.id === id)) {
    const e = new Error('Unknown gateway.'); e.status = 400; throw e;
  }
  const gs = (await store.settings.get('gateways')) || { activeGateway: null, installed: [], gateways: {} };
  gs.activeGateway = gs.activeGateway === id ? null : id;
  await store.settings.set('gateways', gs);
  if (gs.activeGateway === 'nalopay') nalopay.configureKeys(nalopayKeysFrom((gs.gateways || {}).nalopay));
  else if (id === 'nalopay') nalopay.configureKeys(null);
  if (gs.activeGateway === 'mcash') mcash.configureKeys(mcashKeysFrom((gs.gateways || {}).mcash));
  else if (id === 'mcash') mcash.configureKeys(null);
  res.json({ ok: true, activeGateway: gs.activeGateway });
}));

router.delete('/admin/gateways/:id', writeLimiter, requireAdminAuth, ah(async (req, res) => {
  const { id } = req.params;
  const gs = (await store.settings.get('gateways')) || { activeGateway: null, installed: [], gateways: {} };
  gs.installed = (gs.installed || []).filter(x => x !== id);
  if (gs.activeGateway === id) gs.activeGateway = null;
  if (gs.gateways) delete gs.gateways[id];
  await store.settings.set('gateways', gs);
  if (id === 'nalopay') nalopay.configureKeys(null);
  if (id === 'mcash') mcash.configureKeys(null);
  res.json({ ok: true });
}));

module.exports = router;
