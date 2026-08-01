'use strict';
const dns = require('dns').promises;
const net = require('net');
const store = require('./store');
const { hmacSign } = require('./util');

/* Webhook URLs are supplied by merchants and fetched from our server, so an
   unchecked one turns this into an SSRF probe against anything reachable from
   inside the network — cloud metadata at 169.254.169.254, the database, other
   private services. Scheme is validated when the URL is saved; the host has to
   be checked here, at send time, because a public hostname can resolve to a
   private address (and can change between save and send). */
function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 ||                          // 10.0.0.0/8
           a === 127 ||                         // loopback
           a === 0 ||                           // 0.0.0.0/8
           (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12
           (a === 192 && b === 168) ||          // 192.168.0.0/16
           (a === 169 && b === 254) ||          // link-local, incl. cloud metadata
           (a === 100 && b >= 64 && b <= 127);  // carrier-grade NAT
  }
  const v6 = ip.toLowerCase();
  return v6 === '::1' || v6 === '::' ||
         v6.startsWith('fc') || v6.startsWith('fd') ||   // unique local
         v6.startsWith('fe80') ||                        // link-local
         v6.startsWith('::ffff:');                       // IPv4-mapped
}

async function assertPublicHost(urlString) {
  const url = new URL(urlString);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Webhook URL must use http or https.');
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host)) {
    if (isPrivateAddress(host)) throw new Error('Webhook URL resolves to a private address.');
    return;
  }
  const records = await dns.lookup(host, { all: true });
  if (!records.length) throw new Error('Webhook host could not be resolved.');
  if (records.some((r) => isPrivateAddress(r.address))) {
    throw new Error('Webhook URL resolves to a private address.');
  }
}

async function emit(merchant, type, charge) {
  const event = {
    id: 'evt_' + require('crypto').randomBytes(6).toString('hex'),
    merchantId: merchant.id,
    type,
    chargeReference: charge.reference,
    createdAt: Date.now(),
    status: 'skipped',
    responseCode: null,
  };

  if (!merchant.webhookUrl) {
    await store.events.insert(event);
    return event;
  }

  if (!merchant.webhookSecret) {
    event.status = 'failed';
    event.error = 'Webhook secret not configured for this merchant.';
    await store.events.insert(event);
    return event;
  }

  try {
    await assertPublicHost(merchant.webhookUrl);
  } catch (err) {
    event.status = 'blocked';
    event.error = err.message;
    await store.events.insert(event);
    return event;
  }

  const body = JSON.stringify({ id: event.id, type, createdAt: event.createdAt, data: charge });
  const signature = hmacSign(body, merchant.webhookSecret);

  const controller = new AbortController();
  const tid = setTimeout(() => controller.abort(), 10_000);
  try {
    const res = await fetch(merchant.webhookUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'cowrie-signature': signature },
      body,
      signal: controller.signal,
    });
    clearTimeout(tid);
    event.status = res.ok ? 'delivered' : 'failed';
    event.responseCode = res.status;
  } catch (err) {
    clearTimeout(tid);
    event.status = err.name === 'AbortError' ? 'timeout' : 'failed';
    event.error = err.name === 'AbortError' ? 'Webhook timed out after 10 s' : err.message;
  }

  await store.events.insert(event);
  return event;
}

module.exports = { emit };
