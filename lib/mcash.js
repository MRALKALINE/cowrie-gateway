'use strict';
const crypto = require('crypto');

/* MCASH LTD (app.arkmah.com) — hosted checkout only. One POST to
   /payment/initiate returns a redirect URL; the payer completes mobile money
   (MTN / Telecel / AT) or card on MCASH's page and we are told the outcome by
   a signed IPN. There is NO status-lookup endpoint, so unlike Nalopay a charge
   can only be settled by that IPN — which is why its signature is verified
   with a timing-safe compare and the amount is re-checked against our own
   record before anything is marked paid. */

const BASE = process.env.MCASH_BASE_URL || 'https://app.arkmah.com';
const LIVE_INITIATE = `${BASE}/payment/initiate`;
const SANDBOX_INITIATE = `${BASE}/sandbox/payment/initiate`;

/* Static pay-link — the flow used when no API keys are configured. It is a
   fixed MCASH page where the payer types the amount themselves and nothing is
   echoed back to us, so a charge paid through it CANNOT settle automatically:
   it stays pending until an admin checks the MCASH account and uses the
   admin console's mark-paid. The payer's own "I've paid" is never trusted. */
const PAYLINK = process.env.MCASH_PAYLINK_URL || 'https://app.arkmah.com/pay-link/ucauuiujzvfi';
function paylinkUrl() { return PAYLINK; }

/* Unlike Nalopay, MCASH has a real sandbox, so the generic gateway key slots
   map naturally: test* = sandbox pair, live* = live pair. Keys saved in the
   admin console override the env vars, matching lib/nalopay.js. */
let _cachedKeys = null;
function configureKeys(keys) { _cachedKeys = keys || null; }

function creds(mode = 'live') {
  const k = _cachedKeys || {};
  if (mode === 'test') {
    return {
      publicKey: k.testPublicKey || process.env.MCASH_TEST_PUBLIC_KEY || '',
      secretKey: k.testSecretKey || process.env.MCASH_TEST_SECRET_KEY || '',
    };
  }
  return {
    publicKey: k.livePublicKey || process.env.MCASH_PUBLIC_KEY || '',
    secretKey: k.liveSecretKey || process.env.MCASH_SECRET_KEY || '',
  };
}

function configured() {
  const c = creds('live');
  return Boolean(c.publicKey && c.secretKey);
}
function sandboxConfigured() {
  const c = creds('test');
  return Boolean(c.publicKey && c.secretKey);
}

/* KassifyPay stores money in minor units (GHS 1.00 === 100); MCASH takes a
   2-decimal major amount. */
function toMajor(minorUnits) {
  return (Math.round(Number(minorUnits)) / 100).toFixed(2);
}
function toMinor(majorUnits) {
  return Math.round(Number(majorUnits) * 100);
}

/* IPN signature, per the MCASH docs (PHP):
     strtoupper(hash_hmac('sha256', $data['amount'] . $identifier, $secret))
   `amountRaw` must be the amount string exactly as it arrived in the IPN body
   — re-rendering it (e.g. Number(...).toFixed(2)) would break the HMAC when
   MCASH sends "100" rather than "100.00". */
function expectedSignature(amountRaw, identifier, mode = 'live') {
  const { secretKey } = creds(mode);
  return crypto.createHmac('sha256', secretKey)
    .update(`${amountRaw}${identifier}`, 'utf8')
    .digest('hex')
    .toUpperCase();
}

function verifySignature({ amountRaw, identifier, signature, mode = 'live' }) {
  if (!signature || !identifier) return false;
  const expected = expectedSignature(String(amountRaw), String(identifier), mode);
  const got = String(signature).toUpperCase();
  if (got.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(expected, 'utf8'), Buffer.from(got, 'utf8'));
}

/* Starts a hosted checkout session. MCASH's backend reads classic form fields
   (its reference integration is PHP $_POST), so the body is form-encoded, not
   JSON. Success response: { "success": "ok", "url": "https://…" }. */
async function initiate({ mode = 'live', identifier, amountMinor, currency = 'GHS', details, customerName, customerEmail, ipnUrl, successUrl, cancelUrl, siteLogo }) {
  const { publicKey } = creds(mode);
  if (!publicKey) throw new Error('MCASH credentials are not configured.');

  const form = new URLSearchParams({
    public_key: publicKey,
    identifier,
    currency: String(currency || 'GHS').toUpperCase(),
    amount: toMajor(amountMinor),
    details: details || 'Payment',
    customer_name: customerName || 'Customer',
    customer_email: customerEmail,
    ipn_url: ipnUrl,
    success_url: successUrl,
    cancel_url: cancelUrl,
  });
  if (siteLogo) form.set('site_logo', siteLogo);

  const res = await fetch(mode === 'test' ? SANDBOX_INITIATE : LIVE_INITIATE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  const data = await res.json().catch(() => ({}));
  return { httpStatus: res.status, ...data };
}

/* Only "success" is documented; treat the obvious negatives as failed and
   leave anything unrecognised pending so a charge is never marked terminal on
   an unknown value. */
function mapStatus(mcashStatus) {
  switch (String(mcashStatus || '').toLowerCase()) {
    case 'success':
    case 'completed': return 'success';
    case 'failed':
    case 'cancelled':
    case 'canceled':
    case 'error':     return 'failed';
    default:          return 'pending';
  }
}

module.exports = {
  initiate, paylinkUrl, mapStatus, toMajor, toMinor,
  verifySignature, expectedSignature,
  configureKeys, configured, sandboxConfigured, creds,
  BASE,
};
