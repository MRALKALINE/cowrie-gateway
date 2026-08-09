'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const store = require('./lib/store');
const cfg = require('./lib/config');
const api = require('./routes/api');
const partnerLink = require('./routes/partner-link');
const { migrate } = require('./lib/migrate');
const { apiKey } = require('./lib/util');
const { seedAdmins } = require('./lib/admins');
const nalopay = require('./lib/nalopay');
const mcash = require('./lib/mcash');

const app = express();
app.set('trust proxy', true);

/* Security headers on every response. */
/* Each response gets a fresh nonce, stamped onto the inline <script> as the
   page is served. That lets script-src drop 'unsafe-inline': our own script
   runs because it carries the nonce, while anything injected into the page
   does not and is refused. An attacker cannot guess the value — it changes
   per response.

   style-src keeps 'unsafe-inline' deliberately. There are ~490 style
   attributes across these pages, removing them is a rewrite rather than a
   hardening step, and injected CSS cannot execute script. */
function cspFor(nonce) {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: https:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'",
  ].join('; ');
}

app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', cspFor(res.locals.nonce));
  /* Render terminates TLS, so this is only meaningful in production. */
  if (process.env.RENDER) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

/* KYC submits three base64 images and genuinely needs room. Every other route
   needs a fraction of that, and a 20 MB allowance applied globally let anyone
   post 20 MB to any endpoint — including the unauthenticated webhook — and
   have the server buffer it. The large limit is scoped to KYC alone.
   rawBody is retained for any webhook route that needs the unparsed payload. */
const keepRaw = (req, _res, buf) => { req.rawBody = buf; };
app.use('/api/kyc', express.json({ limit: '20mb', verify: keepRaw }));
app.use(express.json({ limit: '256kb', verify: keepRaw }));
app.use(express.urlencoded({ extended: true, limit: '256kb' }));

app.use('/api', api);

/* Hosted partner links live at the root — /p/<code> — because they are shared
   by hand and read aloud. Mounted ahead of the static handler so a partner
   code can never be shadowed by a file of the same name. */
app.use('/p', partnerLink);

const pub = path.join(__dirname, 'public');

/* Pages are served through here rather than sendFile so the per-response
   nonce can be stamped onto the inline <script>. Without that the browser
   would refuse to run it, since script-src no longer allows 'unsafe-inline'.

   File contents are read once and cached; only the nonce differs per
   response, so the substitution is the only per-request work. */
const htmlCache = new Map();
function sendPage(res, name) {
  let html = htmlCache.get(name);
  if (html === undefined) {
    html = fs.readFileSync(path.join(pub, name), 'utf8');
    htmlCache.set(name, html);
  }
  res.type('html').send(
    html.replace(/<script(?![^>]*\ssrc=)/g, `<script nonce="${res.locals.nonce}"`),
  );
}

/* Requesting a page by filename must go through the same path, or it would be
   served raw by express.static with no nonce and a dead script. */
app.get(/\.html$/, (req, res, next) => {
  const name = path.basename(req.path);
  if (!htmlCache.has(name) && !fs.existsSync(path.join(pub, name))) return next();
  sendPage(res, name);
});
/* index:false — otherwise express.static answers "/" with index.html straight
   off disk, before the route below runs, and the page arrives without a nonce
   so its script is refused. */
app.use(express.static(pub, { index: false }));

app.get('/',           (_, res) => sendPage(res, 'index.html'));
app.get('/login',      (_, res) => sendPage(res, 'login.html'));
app.get('/checkout',   (_, res) => sendPage(res, 'checkout.html'));
app.get('/dashboard',  (_, res) => sendPage(res, 'dashboard.html'));
app.get('/register',   (_, res) => sendPage(res, 'register.html'));
app.get('/docs',       (_, res) => sendPage(res, 'docs.html'));
app.get('/admin',      (_, res) => sendPage(res, 'admin.html'));
app.get('/admin-login',(_, res) => sendPage(res, 'admin-login.html'));

app.use('/api', (_, res) => res.status(404).json({ error: 'not_found', message: 'Unknown endpoint.' }));

/* Errors we raise deliberately carry a status and a message written for the
   user. Anything else is an unexpected failure whose message comes from a
   library or an upstream service — those were being forwarded verbatim, which
   is how a database error ended up printed on a merchant's login form. Those
   now log in full with a short reference and return a generic message, so a
   user-reported symptom can be matched to an exact stack trace in the logs. */
app.use((e, req, res, _next) => {
  const status = e.status || 500;
  const expected = Boolean(e.status) && status < 500;

  if (!expected) {
    const ref = Math.random().toString(36).slice(2, 8);
    console.error(`[error ${ref}] ${req.method} ${req.originalUrl} -> ${status}`);
    console.error(e);
    return res.status(status).json({
      error: e.code || 'server_error',
      message: `Something went wrong on our side. Please try again. (ref: ${ref})`,
      ref,
    });
  }

  res.status(status).json({ error: e.code || 'client_error', message: e.message });
});

/* The demo merchant seeding was removed. It recreated itself on every boot
   with a hardcoded password, was hidden from the admin members list, and
   handed out a working payment key via /api/demo/public-key — so live
   integrations picked it up and their payments were collected against an
   account nobody could see. */

async function migrateMerchantKeys() {
  const all = await store.merchants.all();
  let count = 0;
  for (const m of all) {
    let changed = false;
    if (!m.livePublicKey) {
      m.livePublicKey = apiKey('public', 'live');
      m.liveSecretKey = apiKey('secret', 'live');
      changed = true;
    }
    if (!m.webhookSecret) {
      m.webhookSecret = 'whsec_' + apiKey('secret', 'test').slice(16);
      changed = true;
    }
    if (changed) { await store.merchants.update(m); count++; }
  }
  if (count) console.log(`  Provisioned missing keys for ${count} existing merchant(s)`);
}

async function connectWithRetry(maxAttempts = 6, delayMs = 3000) {
  for (let i = 1; i <= maxAttempts; i++) {
    try {
      await migrate();
      return;
    } catch (e) {
      if (i === maxAttempts) throw e;
      console.log(`  [DB] Not ready (attempt ${i}/${maxAttempts}), retrying in ${delayMs / 1000}s…`);
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
}

async function loadGatewaySettings() {
  const gs = (await store.settings.get('gateways')) || { activeGateway: null, installed: [], gateways: {} };

  /* Sync Nalopay env-var credentials into the DB so they show in the admin
     dashboard. Nalopay has no test/live split, so its merchant_id + Basic
     token + secret key are mapped onto the generic slots (see routes/api.js
     nalopayKeysFrom). A slot is only filled when empty, so keys saved by hand
     always win. */
  const envKeys = {
    testPublicKey: process.env.NALOPAY_MERCHANT_ID || '',
    testSecretKey: process.env.NALOPAY_BASIC_AUTH  || '',
    livePublicKey: '',
    liveSecretKey: process.env.NALOPAY_SECRET_KEY  || '',
  };
  if (Object.values(envKeys).some(Boolean)) {
    gs.gateways = gs.gateways || {};
    const existing = gs.gateways.nalopay || {};
    gs.gateways.nalopay = {
      testPublicKey: existing.testPublicKey || envKeys.testPublicKey,
      testSecretKey: existing.testSecretKey || envKeys.testSecretKey,
      livePublicKey: '',
      liveSecretKey: existing.liveSecretKey || envKeys.liveSecretKey,
    };
    gs.installed = gs.installed || [];
    if (!gs.installed.includes('nalopay')) gs.installed.push('nalopay');
    if (!gs.activeGateway) gs.activeGateway = 'nalopay';
    await store.settings.set('gateways', gs);
    console.log('  ✓ Nalopay env-var credentials synced to dashboard');
  }

  const saved = gs.gateways && gs.gateways.nalopay;
  if (saved && saved.testPublicKey && saved.testSecretKey && saved.liveSecretKey) {
    nalopay.configureKeys({
      merchantId: saved.testPublicKey,
      basicAuth:  saved.testSecretKey,
      secretKey:  saved.liveSecretKey,
    });
    console.log('  ✓ Nalopay credentials loaded from database');
  }

  /* Same sync for MCASH (app.arkmah.com). Its slots map directly: test* is
     the sandbox pair, live* the live pair. When MCASH has credentials it also
     takes over as the active gateway unless the admin has explicitly picked
     something other than Nalopay — MCASH replaces Nalopay as the default. */
  const mcashEnv = {
    testPublicKey: process.env.MCASH_TEST_PUBLIC_KEY || '',
    testSecretKey: process.env.MCASH_TEST_SECRET_KEY || '',
    livePublicKey: process.env.MCASH_PUBLIC_KEY || '',
    liveSecretKey: process.env.MCASH_SECRET_KEY || '',
  };
  if (Object.values(mcashEnv).some(Boolean)) {
    gs.gateways = gs.gateways || {};
    const existingM = gs.gateways.mcash || {};
    gs.gateways.mcash = {
      testPublicKey: existingM.testPublicKey || mcashEnv.testPublicKey,
      testSecretKey: existingM.testSecretKey || mcashEnv.testSecretKey,
      livePublicKey: existingM.livePublicKey || mcashEnv.livePublicKey,
      liveSecretKey: existingM.liveSecretKey || mcashEnv.liveSecretKey,
    };
    gs.installed = gs.installed || [];
    if (!gs.installed.includes('mcash')) gs.installed.push('mcash');
    if (!gs.activeGateway || gs.activeGateway === 'nalopay') gs.activeGateway = 'mcash';
    await store.settings.set('gateways', gs);
    console.log('  ✓ MCASH env-var credentials synced to dashboard');
  }

  const savedM = gs.gateways && gs.gateways.mcash;
  if (savedM && ((savedM.livePublicKey && savedM.liveSecretKey) || (savedM.testPublicKey && savedM.testSecretKey))) {
    mcash.configureKeys({
      livePublicKey: savedM.livePublicKey || '',
      liveSecretKey: savedM.liveSecretKey || '',
      testPublicKey: savedM.testPublicKey || '',
      testSecretKey: savedM.testSecretKey || '',
    });
    console.log('  ✓ MCASH credentials loaded from database');
  }
}

function enforceProductionSecurity() {
  // Only warn on Render (RENDER env var is set automatically by the platform)
  if (!process.env.RENDER) return;
  const issues = [];
  if (cfg.SECRET === 'dev_secret_change_me_in_production') {
    issues.push('COWRIE_SECRET is the default dev value — set a strong random string in Render env vars.');
  }
  if (!issues.length) return;
  console.warn('\n⚠️  Security misconfiguration:');
  issues.forEach((i) => console.warn(`   • ${i}`));
  console.warn('');
}

async function start() {
  enforceProductionSecurity();
  await connectWithRetry();
  await migrateMerchantKeys();
  await seedAdmins();
  await loadGatewaySettings();
  app.listen(cfg.PORT, async () => {
    const all = await store.merchants.all();
    const demo = all.filter((m) => m.demo);
    console.log('\n  KassifyPay gateway running');
    console.log(`  -> http://localhost:${cfg.PORT}`);
    const mcashState = mcash.configured() ? 'configured' : (mcash.sandboxConfigured() ? 'sandbox only' : 'NOT CONFIGURED');
    console.log(`  MCASH: ${mcashState} | Nalopay (fallback): ${nalopay.configured() ? 'configured' : 'not configured'}`);
    if (!mcash.configured() && !mcash.sandboxConfigured() && !nalopay.configured()) {
      console.log('  ⚠ No payment provider configured — payments will fail');
    }
    if (demo.length) {
      console.warn(`  ⚠ ${demo.length} demo merchant(s) still present — these accept real payments. Lock or remove them.`);
    }
  });
}

start().catch((e) => { console.error('Failed to start:', e); process.exit(1); });
