'use strict';
const store = require('./store');
const { reference } = require('./util');

/* This module used to be a payment simulator: it moved charges through
   card / mobile-money / bank / USSD states locally and settled them without
   any money changing hands. That was fine when Cowrie was a demo. Once real
   merchants depended on it, the settle paths (submitMethod, authorizeOtp,
   confirmExternal, succeed) became a way for anyone holding a checkout link
   to mark their own order paid, so they were removed along with the routes
   that exposed them.

   Charges are now created here and settled only in routes/api.js via
   confirmWithNalopay(), which re-reads the status from Nalopay rather than
   trusting the caller. */

async function createCharge(merchant, { amount, currency = 'GHS', email, callbackUrl, metadata = {}, openAmount = false, reference: ref }) {
  if (openAmount) {
    amount = 0;
  } else {
    amount = Math.round(Number(amount));
    if (!Number.isFinite(amount) || amount < 100) {
      const e = new Error('amount must be an integer in minor units (>= 100)'); e.status = 400; throw e;
    }
  }
  return store.charges.insert({
    reference: ref || reference(),   // honour a merchant-supplied reference
    merchantId: merchant.id,
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
