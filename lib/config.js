'use strict';

module.exports = {
  PORT: Number(process.env.PORT) || 4000,
  SECRET: process.env.COWRIE_SECRET || 'dev_secret_change_me_in_production',
  DEFAULT_CURRENCY: 'GHS',
  TOKEN_TTL_MS: 24 * 60 * 60 * 1000,
  REMEMBER_TTL_MS: 30 * 24 * 60 * 60 * 1000,
  ADMIN_EMAIL: process.env.ADMIN_EMAIL || 'desmondagrah48@gmail.com,groovyalpha@gmail.com',
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'admin2026',
  /* Nalopay — see lib/nalopay.js. Read there via process.env so the admin
     console can override them at runtime; mirrored here for visibility. */
  NALOPAY_MERCHANT_ID: process.env.NALOPAY_MERCHANT_ID || '',
  NALOPAY_BASIC_AUTH: process.env.NALOPAY_BASIC_AUTH || '',
  NALOPAY_SECRET_KEY: process.env.NALOPAY_SECRET_KEY || '',
};
