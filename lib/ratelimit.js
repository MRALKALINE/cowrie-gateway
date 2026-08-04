'use strict';

/* Fixed-window limiter keyed on client IP.

   Lifted out of routes/api.js so routes defined elsewhere — the hosted partner
   links, which are unauthenticated and create charges — can be capped by the
   same mechanism rather than growing a second copy of it. */
function rateLimit({ windowMs, max }) {
  const hits = new Map();
  // Prune expired entries every 5 min to prevent unbounded Map growth
  setInterval(() => {
    const now = Date.now();
    for (const [k, e] of hits) if (now > e.reset) hits.delete(k);
  }, 5 * 60_000).unref();

  return (req, res, next) => {
    const key = req.ip; const now = Date.now();
    const entry = hits.get(key) || { count: 0, reset: now + windowMs };
    if (now > entry.reset) { entry.count = 0; entry.reset = now + windowMs; }
    entry.count += 1; hits.set(key, entry);
    if (entry.count > max) {
      res.setHeader('Retry-After', Math.ceil((entry.reset - now) / 1000));
      const e = new Error('Too many requests, slow down.'); e.status = 429; return next(e);
    }
    next();
  };
}

module.exports = { rateLimit };
