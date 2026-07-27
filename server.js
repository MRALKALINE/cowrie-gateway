'use strict';
const path = require('path');
const express = require('express');
const store = require('./lib/store');
const cfg = require('./lib/config');
const api = require('./routes/api');
const { migrate } = require('./lib/migrate');
const { merchantId, apiKey, hashPassword } = require('./lib/util');
const nalopay = require('./lib/nalopay');

const app = express();
app.set('trust proxy', true);

/* Security headers on every response */
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

/* KYC submissions send up to 3 base64 images (~7 MB each); keep limit generous.
   rawBody is retained for any webhook route that needs the unparsed payload. */
app.use(express.json({ limit: '20mb', verify: (req, _res, buf) => { req.rawBody = buf; } }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

app.use('/api', api);

const pub = path.join(__dirname, 'public');
app.use(express.static(pub));
app.get('/',           (_, res) => res.sendFile(path.join(pub, 'index.html')));
app.get('/login',      (_, res) => res.sendFile(path.join(pub, 'login.html')));
app.get('/checkout',   (_, res) => res.sendFile(path.join(pub, 'checkout.html')));
app.get('/dashboard',  (_, res) => res.sendFile(path.join(pub, 'dashboard.html')));
app.get('/register',   (_, res) => res.sendFile(path.join(pub, 'register.html')));
app.get('/admin',      (_, res) => res.sendFile(path.join(pub, 'admin.html')));
app.get('/admin-login',(_, res) => res.sendFile(path.join(pub, 'admin-login.html')));

app.use('/api', (_, res) => res.status(404).json({ error: 'not_found', message: 'Unknown endpoint.' }));
app.use((e, _req, res, _next) => {
  const status = e.status || 500;
  if (status >= 500) console.error(e);
  res.status(status).json({ error: e.code || 'server_error', message: e.message || 'Something went wrong.' });
});

async function seedDemoMerchant() {
  const existing = await store.merchants.byEmail('demo@adom.shop');
  if (existing && existing.livePublicKey) return; // fully migrated
  const base = existing || {};
  const merchant = {
    id: base.id || merchantId(),
    businessName: 'Adɔm Stores',
    email: 'demo@adom.shop',
    passwordHash: base.passwordHash || hashPassword('password123'),
    publicKey:  base.publicKey  || apiKey('public',  'test'),
    secretKey:  base.secretKey  || apiKey('secret',  'test'),
    livePublicKey:  base.livePublicKey  || apiKey('public',  'live'),
    liveSecretKey:  base.liveSecretKey  || apiKey('secret',  'live'),
    webhookSecret: base.webhookSecret || ('whsec_' + apiKey('secret', 'test').slice(16)),
    webhookUrl: base.webhookUrl || null,
    demo: true,
    createdAt: base.createdAt || Date.now(),
  };
  if (existing) {
    await store.merchants.update(merchant);
    console.log('  Updated demo merchant (added live keys)');
  } else {
    await store.merchants.insert(merchant);
    console.log('  Seeded demo merchant: demo@adom.shop / password123');
  }
}

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
  await seedDemoMerchant();
  await migrateMerchantKeys();
  await loadGatewaySettings();
  app.listen(cfg.PORT, async () => {
    const all = await store.merchants.all();
    const demo = all.find((m) => m.demo);
    console.log('\n  Cowrie gateway running');
    console.log(`  -> http://localhost:${cfg.PORT}`);
    console.log(`  Nalopay: ${nalopay.configured() ? 'configured' : 'NOT CONFIGURED — payments will fail'}`);
    if (demo) console.log(`  Demo Cowrie key: ${demo.publicKey}  (not a gateway key)`);
  });
}

start().catch((e) => { console.error('Failed to start:', e); process.exit(1); });
