'use strict';

module.exports = {
  PORT: Number(process.env.PORT) || 4000,
  SECRET: process.env.COWRIE_SECRET || 'dev_secret_change_me_in_production',
  DEFAULT_CURRENCY: 'GHS',
  TOKEN_TTL_MS: 24 * 60 * 60 * 1000,
  REMEMBER_TTL_MS: 30 * 24 * 60 * 60 * 1000,
  /* No defaults: a fallback password in source is a credential in source.
     Admin accounts live in the `admins` table — see lib/admins.js. ADMIN_EMAIL
     is still used as the recipient list for deposit and transfer alerts. */
  ADMIN_EMAIL: process.env.ADMIN_EMAIL || '',
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || '',
  /* MCASH (app.arkmah.com) — see lib/mcash.js. Read there via process.env so
     the admin console can override them at runtime; mirrored for visibility. */
  MCASH_PUBLIC_KEY: process.env.MCASH_PUBLIC_KEY || '',
  MCASH_SECRET_KEY: process.env.MCASH_SECRET_KEY || '',
  MCASH_TEST_PUBLIC_KEY: process.env.MCASH_TEST_PUBLIC_KEY || '',
  MCASH_TEST_SECRET_KEY: process.env.MCASH_TEST_SECRET_KEY || '',
  /* Nalopay (fallback gateway) — see lib/nalopay.js. */
  NALOPAY_MERCHANT_ID: process.env.NALOPAY_MERCHANT_ID || '',
  NALOPAY_BASIC_AUTH: process.env.NALOPAY_BASIC_AUTH || '',
  NALOPAY_SECRET_KEY: process.env.NALOPAY_SECRET_KEY || '',
};
