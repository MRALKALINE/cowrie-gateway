'use strict';
const { genId } = require('./util');

/* Partners — people who bring deposits to a merchant and earn a share of what
   they bring in.

   A partner belongs to one merchant and is stored on that merchant's record,
   because the list is short, is only ever read alongside the merchant, and is
   only ever edited by an admin. That keeps it out of the migration path
   entirely: a merchant with no `partners` key simply has none.

   Commission is a share of the deposit — the merchant's own figure, before the
   platform fee is added on top. A GHS 100 deposit at 10% is GHS 10 to the
   partner whatever the platform charges the payer, so the two rates never
   interfere with each other. */

const MAX_COMMISSION_BPS = 5000;   // 50% — a guard against a slipped decimal

function list(merchant) {
  return Array.isArray(merchant && merchant.partners) ? merchant.partners : [];
}

/* Codes travel in URLs and get read aloud over the phone, so they are lowercase
   and limited to characters that survive both. */
function normaliseCode(raw) {
  return String(raw || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 32);
}

/* A code has to be unique across every merchant, not just this one, because a
   hosted link carries nothing but the code. */
function codeTaken(allMerchants, code, exceptPartnerId) {
  return allMerchants.some((m) => list(m).some((p) => p.code === code && p.id !== exceptPartnerId));
}

function uniqueCode(allMerchants, desired, fallbackName) {
  const base = normaliseCode(desired) || normaliseCode(fallbackName) || 'partner';
  if (!codeTaken(allMerchants, base)) return base;
  for (let i = 2; i < 200; i++) {
    const candidate = `${base}-${i}`;
    if (!codeTaken(allMerchants, candidate)) return candidate;
  }
  return `${base}-${genId('').slice(0, 6)}`;
}

function byCode(merchant, code) {
  const c = normaliseCode(code);
  if (!c) return null;
  return list(merchant).find((p) => p.code === c) || null;
}

function byId(merchant, id) {
  return list(merchant).find((p) => p.id === id) || null;
}

/* Searches every merchant — the hosted link route has only a code to go on. */
function findAnywhere(allMerchants, code) {
  const c = normaliseCode(code);
  if (!c) return null;
  for (const m of allMerchants) {
    const p = byCode(m, c);
    if (p) return { merchant: m, partner: p };
  }
  return null;
}

/* ── Attribution by the merchant's own user id ──────────────────────────────
   Agrah's site sends metadata.userId with every deposit and nothing else that
   identifies anyone. The partner relationship exists over there, keyed by that
   same id — so given a list of which users belong to which partner, deposits
   can be credited without Agrah changing a line of their integration. */

function parseUserIds(input) {
  const raw = Array.isArray(input) ? input : String(input || '').split(/[\s,;]+/);
  const seen = new Set();
  for (const x of raw) {
    const v = String(x || '').trim();
    if (v && v.length <= 128) seen.add(v);
  }
  return [...seen].slice(0, 20000);
}

function userIds(partner) {
  return Array.isArray(partner && partner.userIds) ? partner.userIds : [];
}

function byUserId(merchant, userId) {
  const id = String(userId || '').trim();
  if (!id) return null;
  return list(merchant).find((p) => p.active !== false && userIds(p).includes(id)) || null;
}

/* The id a deposit carries, wherever the merchant chose to put it. */
function userIdOf(charge) {
  const m = (charge && charge.metadata) || {};
  return m.userId || m.user_id || m.customerId || m.customer_id || null;
}

/* A partner code sent alongside a deposit. Merchants name this field however
   their own system names it, and refusing every spelling but one would mean
   silently crediting nobody. */
function codeFrom(body, query) {
  const b = body || {}; const q = query || {}; const m = b.metadata || {};
  return b.partner || b.partnerCode || b.ref || b.affiliate || b.agent
      || m.partner || m.partnerCode || m.ref || m.affiliate || m.agent
      || q.ref || q.partner || null;
}

function commissionFor(amountMinor, bps) {
  const base = Math.max(0, Math.round(Number(amountMinor) || 0));
  const rate = Math.max(0, Math.min(MAX_COMMISSION_BPS, Math.round(Number(bps) || 0)));
  return Math.round((base * rate) / 10000);
}

/* Stamps the attribution onto a charge. The rate is written down here rather
   than looked up at reporting time, so re-rating a partner never restates what
   they have already earned. */
function attach(charge, partner) {
  if (!partner) return charge;
  charge.partnerId = partner.id;
  charge.partnerCode = partner.code;
  charge.partnerName = partner.name;
  charge.partnerBps = Math.round(Number(partner.commissionBps) || 0);
  charge.partnerCommission = commissionFor(charge.amount, charge.partnerBps);
  return charge;
}

/* Re-run when an open-amount deposit finally gets a figure — the commission
   was zero until the payer typed one. The rate stays as attached. */
function recompute(charge) {
  if (!charge.partnerId) return charge;
  charge.partnerCommission = commissionFor(charge.amount, charge.partnerBps);
  return charge;
}

module.exports = {
  MAX_COMMISSION_BPS,
  list, normaliseCode, codeTaken, uniqueCode, byCode, byId, findAnywhere,
  parseUserIds, userIds, byUserId, userIdOf, codeFrom,
  commissionFor, attach, recompute,
};
