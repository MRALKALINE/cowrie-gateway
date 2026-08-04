'use strict';
const store = require('./store');
const { reference } = require('./util');
const fees = require('./fees');

/* This module used to be a payment simulator: it moved charges through
   card / mobile-money / bank / USSD states locally and settled them without
   any money changing hands. That was fine when KassifyPay was a demo. Once real
   merchants depended on it, the settle paths (submitMethod, authorizeOtp,
   confirmExternal, succeed) became a way for anyone holding a checkout link
   to mark their own order paid, so they were removed along with the routes
   that exposed them.

   Charges are now created here and settled only in routes/api.js via
   confirmWithNalopay(), which re-reads the status from Nalopay rather than
   trusting the caller. */

/* Matches MAX_AMOUNT_MAJOR in routes/api.js — 1,000,000 major units. */
const MAX_AMOUNT_MINOR = 100_000_000;

async function createCharge(merchant, { amount, currency = 'GHS', email, callbackUrl, metadata = {}, openAmount = false, reference: ref, mode = 'test', idempotencyKey = null }) {
  if (openAmount) {
    amount = 0;
  } else {
    /* MINOR units here (5000 === GHS 50.00). Validate before rounding:
       Math.round(Infinity) is Infinity, which passes a bare `< 100` check and
       is then serialised to null by JSON.stringify. */
    const raw = Number(amount);
    if (!Number.isFinite(raw) || raw < 100 || raw > MAX_AMOUNT_MINOR) {
      const e = new Error(`amount must be an integer in minor units between 100 and ${MAX_AMOUNT_MINOR}`);
      e.status = 400; throw e;
    }
    amount = Math.round(raw);
  }
  /* feeAmount and totalAmount are set here so they exist from the moment a
     charge does. amount stays the merchant's figure — every revenue number on
     the dashboards reads it, and none of them should include our fee.

     The rate is the merchant's own where one has been set, falling back to the
     platform default. It is written onto the charge, so a rate changed later
     never restates what this one cost. */
  const bps = fees.feeBpsForMerchant(merchant);
  const feeAmount = fees.feeFor(amount, bps);

  return store.charges.insert({
    reference: ref || reference(),   // honour a merchant-supplied reference
    feeAmount,
    totalAmount: amount + feeAmount,
    feeBps: bps,
    merchantId: merchant.id,
    /* mode and idempotencyKey are set here rather than patched on afterwards:
       the unique index that makes idempotency race-proof can only fire if the
       key is present in the original INSERT. */
    mode,
    idempotencyKey,
    amount,
    currency,
    openAmount: openAmount || false,
    customerEmail: email || null,
    callbackUrl: callbackUrl || null,
    status: 'pending',
    method: null,
    auth: null,
    nextAction: null,
    metadata,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    paidAt: null,
  });
}

module.exports = { createCharge };
