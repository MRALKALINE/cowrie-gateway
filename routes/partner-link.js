'use strict';
const express = require('express');
const store = require('../lib/store');
const payments = require('../lib/payments');
const partners = require('../lib/partners');
const { rateLimit } = require('../lib/ratelimit');

/* Hosted partner links: https://<host>/p/<code>

   One link, shared once, used by any number of depositors — each visit raises
   its own charge, tagged with the partner, and hands the payer straight to the
   checkout. That is what separates this from a payment link, which is a single
   charge and is spent the moment somebody pays it.

   Unauthenticated by necessity: the whole point is that a depositor can follow
   it with nothing but the URL. So it is capped, and it refuses outright unless
   the merchant behind it is verified and in good standing. */
const router = express.Router();

/* Deliberately tighter than the API's charge limiter — nobody follows a
   deposit link twenty times a minute by hand. */
const linkLimiter = rateLimit({ windowMs: 60_000, max: 20 });

/* A refusal here is read by a depositor, not a developer, so it is a page
   rather than JSON and it says what to do next. */
function refuse(res, status, heading, detail) {
  res.status(status).type('html').send(`<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${heading}</title>
<style>
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0B1620;color:#E8EEF2;
       font-family:system-ui,-apple-system,"Segoe UI",sans-serif;padding:24px}
  .card{max-width:420px;text-align:center;background:rgba(255,255,255,.04);
        border:1px solid rgba(255,255,255,.1);border-radius:18px;padding:32px 28px}
  h1{font-size:19px;margin:0 0 10px}
  p{margin:0;font-size:14px;line-height:1.6;color:rgba(232,238,242,.65)}
</style>
<div class="card"><h1>${heading}</h1><p>${detail}</p></div>`);
}

router.get('/:code', linkLimiter, async (req, res, next) => {
  try {
    const all = await store.merchants.all();
    const hit = partners.findAnywhere(all, req.params.code);
    if (!hit) {
      return refuse(res, 404, 'This link is not active',
        'Check the link with whoever gave it to you — it may have been mistyped or withdrawn.');
    }
    const { merchant, partner } = hit;

    if (partner.active === false) {
      return refuse(res, 403, 'This link has been switched off',
        'The partner who shared it is no longer taking deposits. Please contact them directly.');
    }
    if (merchant.locked) {
      return refuse(res, 403, `${merchant.businessName} is not accepting payments`,
        'This account has been deactivated. Please contact the business directly.');
    }
    /* Same gate the live API keys sit behind: real money only moves for a
       verified merchant. Without this a partner link would be a way around it. */
    if (merchant.kycStatus !== 'approved') {
      return refuse(res, 403, `${merchant.businessName} cannot take deposits yet`,
        'This business has not finished verification. Please try again later.');
    }

    /* Optional preset, for a partner sending someone a specific figure.
       Anything else — including nonsense — falls back to letting the payer
       choose, rather than failing the deposit. */
    const asked = Number(req.query.amount);
    const fixed = Number.isFinite(asked) && asked >= 1 && asked <= 1_000_000;

    const charge = await payments.createCharge(merchant, {
      amount: fixed ? Math.round(asked * 100) : 0,
      currency: 'GHS',
      openAmount: !fixed,
      mode: 'live',
      metadata: { source: 'partner_link', partner: partner.code },
    });
    partners.attach(charge, partner);
    charge.partnerLink = true;
    await store.charges.update(charge);

    res.redirect(302, `/checkout?reference=${encodeURIComponent(charge.reference)}`);
  } catch (e) { next(e); }
});

module.exports = router;
