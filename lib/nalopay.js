'use strict';
const crypto = require('crypto');

const BASE = process.env.NALOPAY_BASE_URL || 'https://api.nalopay.com';

/* Nalopay credentials are a triple, not a key pair:
     merchantId  — public-ish account identifier, sent in every body
     basicAuth   — the Basic Auth token, ONLY used to mint a JWT
     secretKey   — used to HMAC-sign each request (trans_hash); never transmitted
   Keys loaded from the DB (admin console) override the env vars, matching
   how lib/paystack.js behaves. */
let _cachedKeys = null;
function configureKeys(keys) { _cachedKeys = keys || null; _token = null; }

function creds() {
  const k = _cachedKeys || {};
  return {
    merchantId: k.merchantId || process.env.NALOPAY_MERCHANT_ID || '',
    basicAuth:  k.basicAuth  || process.env.NALOPAY_BASIC_AUTH  || '',
    secretKey:  k.secretKey  || process.env.NALOPAY_SECRET_KEY  || '',
  };
}

function configured() {
  const c = creds();
  return Boolean(c.merchantId && c.basicAuth && c.secretKey);
}

/* ── amounts ──────────────────────────────────────────────────────────────
   KassifyPay stores money in minor units (GHS 1.00 === 100). Nalopay expects
   major units as a 2-decimal value, and the same rendering must go into the
   hash or it fails verification. Every conversion goes through here. */
function toMajor(minorUnits) {
  return (Math.round(Number(minorUnits)) / 100).toFixed(2);
}
function toMinor(majorUnits) {
  return Math.round(Number(majorUnits) * 100);
}

/* ── signing ──────────────────────────────────────────────────────────────
   trans_hash = HMAC-SHA256(concat(fields, no separators), secretKey) as hex.
   Field order differs between the two products — see the Postman docs. */
function hmac(message) {
  return crypto.createHmac('sha256', creds().secretKey).update(message, 'utf8').digest('hex');
}
function signCollection({ merchantId, accountNumber, amount, reference }) {
  return hmac(`${merchantId}${accountNumber}${amount}${reference}`);
}
function signCheckout({ merchantId, orderId, totalPrice, reference }) {
  return hmac(`${merchantId}${orderId}${totalPrice}${reference}`);
}

/* ── auth token ───────────────────────────────────────────────────────────
   The JWT is short-lived (~15 min in the reference response), so it is cached
   and refreshed 60s before its own `exp` rather than fetched per request. */
let _token = null; // { value, expiresAt }

function jwtExpiry(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString('utf8'));
    if (payload.exp) return payload.exp * 1000;
  } catch { /* fall through to the conservative default */ }
  return Date.now() + 10 * 60_000;
}

async function generateToken() {
  const { merchantId, basicAuth } = creds();
  if (!merchantId || !basicAuth) throw new Error('Nalopay credentials are not configured.');

  const res = await fetch(`${BASE}/clientapi/generate-payment-token/`, {
    method: 'POST',
    headers: {
      Authorization: basicAuth.startsWith('Basic ') ? basicAuth : `Basic ${basicAuth}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ merchant_id: merchantId }),
  });
  const data = await res.json().catch(() => ({}));
  if (!data.success || !data.data || !data.data.token) {
    const cause = data.error ? `${data.error.cause}: ${data.error.description}` : (data.code || res.status);
    throw new Error(`Nalopay token request failed (${cause})`);
  }
  return data.data.token;
}

async function token() {
  if (_token && Date.now() < _token.expiresAt) return _token.value;
  const value = await generateToken();
  _token = { value, expiresAt: jwtExpiry(value) - 60_000 };
  return value;
}

async function post(path, body, withToken = true) {
  const headers = { 'Content-Type': 'application/json' };
  if (withToken) headers.token = await token();

  const res = await fetch(`${BASE}${path}`, {
    method: 'POST', headers, body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  return { httpStatus: res.status, ...data };
}

/* ── collections (direct mobile money) ────────────────────────────────────
   Returns { order_id, status: 'PENDING', amount, timestamp, otp_code }.
   `otp_code` is a USSD string for the payer to dial to approve — it is NOT
   an OTP submitted back to the API. Nalopay has no submit-OTP endpoint. */
async function collection({ accountNumber, accountName, network, amountMinor, reference, callbackUrl, description, extraData }) {
  const { merchantId } = creds();
  const amount = toMajor(amountMinor);

  const body = {
    merchant_id: merchantId,
    service_name: 'MOMO_TRANSACTION',
    trans_hash: signCollection({ merchantId, accountNumber, amount, reference }),
    account_number: accountNumber,
    account_name: accountName || 'Customer',
    network,                       // MTN | AT | TELECEL
    amount,
    reference,
    callback: callbackUrl,
  };
  if (description) body.description = description;
  if (extraData) body.extra_data = extraData;

  return post('/clientapi/collection/', body);
}

/* Status is looked up by Nalopay's order_id, NOT by our reference — the
   order_id from collection()/checkoutSession() must be persisted. */
async function collectionStatus(orderId) {
  const { merchantId } = creds();
  return post('/clientapi/collection-status/', { merchant_id: merchantId, order_id: orderId });
}

/* ── hosted checkout (cards, or any method) ───────────────────────────────
   Returns { checkout_url, checkout_timeout } — a full redirect URL. There is
   no inline/access-code mode as with Paystack. */
async function checkoutSession({ orderId, customerName, referralUrl, callbackUrl, reference, mode = 'ANY', products = [], itemCount, totalMinor }) {
  const { merchantId } = creds();
  const totalPrice = toMajor(totalMinor);

  return post('/checkout/session/', {
    merchant: {
      merchant_id: merchantId,
      order_id: orderId,
      customer_name: customerName || 'Customer',
      referral_url: referralUrl,
      callback_url: callbackUrl,
      trans_hash: signCheckout({ merchantId, orderId, totalPrice, reference }),
      reference,
      mode,                        // MOMO | CARD | ANY
    },
    summary: {
      products,
      item_count: itemCount != null ? itemCount : products.reduce((n, p) => n + (p.count || 1), 0),
      total_price: totalPrice,
    },
  });
}

/* ── status mapping ───────────────────────────────────────────────────────
   Nalopay exposes three states only. Anything unrecognised stays pending so
   a charge is never marked terminal on an unknown value. */
function mapStatus(nalopayStatus) {
  switch (String(nalopayStatus || '').toUpperCase()) {
    case 'COMPLETED':
    case 'SUCCESS':   return 'success';
    case 'FAILED':
    case 'CANCELLED': return 'failed';
    default:          return 'pending';
  }
}

module.exports = {
  collection, collectionStatus, checkoutSession,
  mapStatus, toMajor, toMinor,
  signCollection, signCheckout,
  configureKeys, configured, creds,
  token, generateToken,
  BASE,
};
