'use strict';

/* Fixed rates: rates[currency] = units of that currency per 1 USD.
   e.g. NGN: 1395.625 means 1 USD = 1395.625 NGN, GHS: 12 means 1 USD = 12 GHS.

   These are hardcoded and never refreshed, so any non-GHS amount is converted
   at a stale rate. That is tolerable only because the gateway settles in GHS
   and every live charge is already GHS. Anything that starts accepting real
   foreign currency needs a live rate source before these numbers can be
   trusted for balances or payouts. */
const FIXED_RATES = { NGN: 1395.625, GHS: 12, EUR: 0.93, GBP: 0.79, KES: 130, ZAR: 18.5 };

async function getRates() { return FIXED_RATES; }

/* Convert amountMinor from any currency to USD cents (kept for reference). */
function toUsdMinor(amountMinor, currency, rates) {
  if (!currency || currency === 'USD') return amountMinor;
  const rate = (rates || FIXED_RATES)[currency];
  if (!rate) return amountMinor;
  return Math.round(amountMinor / rate);
}

/* Convert amountMinor from any currency to GHS pesewas.
   Via USD as the common base: GHS_pesewas = (amount / src_rate) * GHS_rate

   The active gateway (Nalopay) settles only in GHS and lib/nalopay.js sends no
   currency at all, so in practice everything collected is already cedis and
   this is an identity function. It still matters for historical charges and
   for anything created with an explicit foreign currency.

   An unrecognised currency returns the amount unchanged, i.e. treats it as GHS
   — the only safe default, since inventing a rate would misstate a balance.
   It is logged because silently doing so is how a number goes wrong unnoticed. */
const warned = new Set();
function toGhsMinor(amountMinor, currency, rates) {
  const r = rates || FIXED_RATES;
  if (!currency || currency === 'GHS') return amountMinor;
  if (currency === 'USD') return Math.round(amountMinor * r.GHS);
  const srcRate = r[currency];
  if (!srcRate) {
    if (!warned.has(currency)) {
      warned.add(currency);
      console.warn(`[fx] No rate for ${currency} — amounts are being counted as GHS 1:1.`);
    }
    return amountMinor;
  }
  return Math.round((amountMinor / srcRate) * r.GHS);
}

/* Merchants hold two balances: NGN, collected by manual transfer into the
   Nigerian bank accounts, and GHS for everything else. Naira is kept as naira
   and never runs through the fixed rate above, so an NGN balance is exactly
   what landed in the bank and can be paid out as naira. */
const BALANCE_CURRENCIES = ['GHS', 'NGN'];
function balanceCurrency(currency) {
  return String(currency || 'GHS').toUpperCase() === 'NGN' ? 'NGN' : 'GHS';
}

/* amountMinor's contribution to the `bucket` balance, in that currency's minor
   units: zero when the charge belongs to the other balance. */
function toBalanceMinor(amountMinor, currency, bucket, rates) {
  if (balanceCurrency(currency) !== bucket) return 0;
  return bucket === 'NGN' ? amountMinor : toGhsMinor(amountMinor, currency, rates);
}

module.exports = { getRates, toUsdMinor, toGhsMinor, BALANCE_CURRENCIES, balanceCurrency, toBalanceMinor };
