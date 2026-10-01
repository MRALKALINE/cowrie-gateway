# KassifyPay — a fully functional demo payment gateway

A small but real payment-gateway backend (Node/Express) that links the KassifyPay
front-end pages — **landing → login → checkout → dashboard** — and makes the
gateway actually work end to end.

The "bank / card network / mobile-money operator" side is *simulated* (you can't
call Visa or MTN from a laptop), but everything the **gateway** itself does is
real: charge creation, a server-side state machine, card validation (Luhn),
3-D Secure / OTP, idempotency, hashed-password auth, API keys, signed webhooks,
and persisted transactions.

## Run it

```bash
npm install      # only dependency is express
npm start        # -> http://localhost:4000
```

Open **http://localhost:4000**.

| Page | URL | Notes |
|------|-----|-------|
| Landing | `/` | links to login + checkout |
| Login | `/login` | demo merchant: `demo@adom.shop` / `password123` |
| Checkout | `/checkout` | the hosted payment page (the gateway) |
| Dashboard | `/dashboard` | payments appear here live after you pay (requires login) |
| Admin | `/admin` | a separate front-end-only demo UI; not wired to the backend |

Test instruments (test mode): card `4242 4242 4242 4242`, any future expiry, any
CVV, OTP `123456`. Mobile money / bank / USSD auto-confirm to simulate the
operator callback.

## How the pieces link

```
 Landing (/)  ──"Sign in"──▶  Login (/login)  ──POST /api/auth/login──▶  Dashboard (/dashboard)
      │                                                                        ▲
      └──"Try a live payment"──▶  Checkout (/checkout)                        │
                                      │                                       │
                       GET  /api/demo/public-key   (test-mode publishable key)│
                       POST /api/charges                                      │
                       POST /charges/:ref/method      payment succeeds ───────┘
                       POST /charges/:ref/authorize | confirm    (and a signed webhook fires)
                       GET  /charges/:ref  (poll)
```

`/checkout` creates its own charge client-side using the demo public key when
no `?reference=` is in the URL (mirroring how a real publishable key is used
in the browser); a real integration instead creates the charge **server-side**
with the secret key and redirects the customer to `/checkout?reference=...`
(see the integration example below).

## API

All JSON. Amounts are in **minor units** (e.g. `25000` = GHS 250.00).

### Auth (merchant)
- `POST /api/auth/register` `{ businessName, email, password }`
- `POST /api/auth/login` `{ email, password }` → `{ token, merchant }`
- `GET  /api/me` (Bearer token)
- `PUT  /api/me/webhook` `{ url }`
- `GET  /api/transactions` (Bearer token)
- `GET  /api/events` (webhook delivery log)

### Charges (the gateway)
- `POST /api/charges` `{ amount, currency, email }` — auth via `public_key`
  (in body or `X-Public-Key`) or a secret key. Supports `Idempotency-Key` header.
- `GET  /api/charges/:reference` — status (poll this)
- `POST /api/charges/:reference/method` `{ method, details }`
  where method ∈ `card | mobile_money | bank_transfer | ussd`
- `POST /api/charges/:reference/authorize` `{ otp }` — card 3-D Secure
- `POST /api/charges/:reference/confirm` — momo / bank / ussd confirmation
- `GET  /api/demo/public-key` — test-mode convenience used by `/checkout`

### Webhooks
On `charge.success` / `charge.failed`, KassifyPay POSTs a JSON event to the
merchant's `webhook_url` with header `cowrie-signature` =
`HMAC_SHA256(rawBody, webhook_secret)`. Verify it before trusting the payload.

## Server-side example (real integration shape)

```js
// 1. your server creates the charge with your SECRET key
const res = await fetch('http://localhost:4000/api/charges', {
  method: 'POST',
  headers: { 'content-type': 'application/json', 'x-public-key': SECRET_KEY },
  body: JSON.stringify({ amount: 25000, currency: 'GHS', email: 'ama@adom.shop' }),
});
const { charge } = await res.json();
// 2. redirect the customer to: /checkout?reference=<charge.reference>
// 3. trust the signed webhook (or poll GET /api/charges/<charge.reference>) for success
```

## Project layout

```
server.js            Express app + page routing + demo seed
routes/api.js        all REST endpoints + auth/rate-limit middleware
lib/payments.js       charge state machine (the gateway logic)
lib/partners.js       partner attribution, PIN auth, earned-vs-withdrawn balance
lib/webhooks.js       signed webhook dispatch
lib/store.js          JSON persistence (swap for Postgres in prod)
lib/util.js           scrypt hashing, HMAC tokens, Luhn, key/ID generation
lib/config.js         secret + port + currency
public/              index · login · register · checkout · dashboard · partner · admin
```

## Partners

Partners are people who bring deposits to a merchant and earn a share of them.
An admin creates them from **Members → a merchant → Partners**, which gives them
a hosted link (`/p/<code>`) and a commission rate.

Each partner can then sign in at **`/partner`** with their code and a PIN the
admin sets on their card, see what they have earned, and withdraw it. Set the
PIN from the same Partners panel — until one is set they cannot sign in.

Withdrawal is deliberately unrestricted: no minimum, no daily cap, no cooldown,
no fee, no approval step and no KYC gate. A partner takes any part of what they
have earned, as often as they like. The only limit is that they cannot withdraw
more than they have actually earned.

A request is recorded as `pending` and appears under **Admin → Payouts** next
to the merchant requests. Nothing sends the money automatically — mark it done
once you have sent it.

| Endpoint | Purpose |
|----------|---------|
| `POST /api/partner/login` | `{ code, pin }` → `{ token, partner }` |
| `GET  /api/partner/me` | balance, earnings and withdrawal history |
| `POST /api/partner/withdraw` | `{ method, amount, …destination }` |

Admin-only: `PUT /api/admin/members/:merchantId/partners/:partnerId/pin`,
`GET /api/admin/partner-payouts`, `POST /api/admin/partner-payouts/:id/complete`.

## Going to production (what to change)
- Replace `lib/store.js` with a real database (Postgres + Prisma).
- Set `COWRIE_SECRET` (token-signing key) via environment, never the default.
- Put it behind HTTPS; serve the checkout from your own domain.
- Integrate real acquiring / card-network and mobile-money operator APIs in
  `lib/payments.js` where the success is currently simulated.
- Add retry/backoff to webhook delivery and store raw events for replay.
