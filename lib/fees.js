'use strict';

/* Platform fee.

   The fee is added on top of what the merchant asked for, not taken out of it:
   a merchant raising a GHS 300 charge is paid GHS 300 and the payer is charged
   GHS 309. Keeping the two apart is what lets every revenue figure on the
   dashboards keep reading `amount` and stay correct — the merchant's earnings
   never include our cut.

   Held in basis points so the rate is exact: 300 bps is 3%, and there is no
   floating-point rate to drift. Override with PLATFORM_FEE_BPS.

   The rate in force is written onto each charge as feeBps when it is created,
   so a charge raised under an earlier rate keeps its own figure and history
   stays truthful. */
const DEFAULT_FEE_BPS = 300;

function feeBps() {
  const raw = Number(process.env.PLATFORM_FEE_BPS);
  if (!Number.isFinite(raw) || raw < 0 || raw > 10000) return DEFAULT_FEE_BPS;
  return Math.round(raw);
}

/* A merchant may carry their own rate; without one they get the platform
   default. Stored per merchant rather than derived, so changing the default
   later never silently re-prices an agreement already struck with someone. */
function feeBpsForMerchant(merchant) {
  const own = merchant && merchant.feeBps;
  if (own === null || own === undefined || own === '') return feeBps();
  const n = Number(own);
  if (!Number.isFinite(n) || n < 0 || n > 10000) return feeBps();
  return Math.round(n);
}

/* Fee on an amount in minor units. Rounded to the nearest minor unit, so a
   fee is never a fraction of a pesewa. `bps` overrides the platform rate —
   pass feeBpsForMerchant(merchant) to price a specific store. */
function feeFor(amountMinor, bps) {
  const base = Math.max(0, Math.round(Number(amountMinor) || 0));
  const rate = (bps === undefined || bps === null) ? feeBps() : Math.round(Number(bps) || 0);
  return Math.round((base * rate) / 10000);
}

/* What the payer is charged: the merchant's amount plus the fee. */
function totalFor(amountMinor, bps) {
  const base = Math.max(0, Math.round(Number(amountMinor) || 0));
  return base + feeFor(base, bps);
}

/* Applied to a charge record at creation and whenever an open amount is set,
   so the three values always agree with each other. */
function applyFee(charge, bps) {
  const rate = (bps === undefined || bps === null) ? feeBps() : Math.round(Number(bps) || 0);
  charge.feeAmount = feeFor(charge.amount, rate);
  charge.totalAmount = charge.amount + charge.feeAmount;
  charge.feeBps = rate;
  return charge;
}

/* Older charges predate these fields; they were collected without a fee, so
   the payer total is simply the amount. */
function payableAmount(charge) {
  return Number.isFinite(charge.totalAmount) ? charge.totalAmount : charge.amount;
}

module.exports = { feeBps, feeBpsForMerchant, feeFor, totalFor, applyFee, payableAmount, DEFAULT_FEE_BPS };
