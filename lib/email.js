'use strict';
const nodemailer = require('nodemailer');

const BASE_URL = (process.env.BASE_URL || 'https://cowrie-gateway.onrender.com').replace(/\/$/, '');

function escHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/* ─── Unified send — Resend preferred, Gmail fallback ─── */
async function sendEmail({ to, subject, html, text }) {
  /* to can be a string or array of strings */
  const recipients = Array.isArray(to) ? to.filter(Boolean) : [to].filter(Boolean);
  if (!recipients.length) return;

  const resendKey = process.env.RESEND_API_KEY;
  const gmailUser = process.env.GMAIL_USER;
  const gmailPass = process.env.GMAIL_APP_PASSWORD;

  /* Resend is primary, Gmail is the fallback — and the fallback must engage
     when Resend FAILS, not only when it is unconfigured. Resend's free tier
     is 100 emails/day; once that is exhausted every send throws, which took
     down registration entirely because the signup OTP could not be sent. */
  const failures = [];

  if (resendKey) {
    try {
      const from = process.env.EMAIL_FROM || 'KassifyPay <onboarding@resend.dev>';
      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${resendKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ from, to: recipients, subject, html, text }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.message || `HTTP ${res.status}`);
      }
      return;
    } catch (e) {
      failures.push(`Resend: ${e.message}`);
      console.warn(`[Email] Resend failed (${e.message}) — falling back to Gmail`);
    }
  }

  if (gmailUser && gmailPass) {
    try {
      const t = nodemailer.createTransport({ service: 'gmail', auth: { user: gmailUser, pass: gmailPass } });
      await t.sendMail({ from: `"KassifyPay" <${gmailUser}>`, to: recipients.join(', '), subject, html, text });
      return;
    } catch (e) {
      failures.push(`Gmail: ${e.message}`);
    }
  }

  if (failures.length) throw new Error(failures.join(' | '));
  console.log(`[Email] No provider configured — would send "${subject}" to ${recipients.join(', ')}`);
}

/* ─── OTP ─── */
async function sendOtp(to, otp, businessName) {
  const name = businessName || 'there';
  await sendEmail({
    to,
    subject: 'Your KassifyPay verification code',
    html: `
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f2f6f7;font-family:'Helvetica Neue',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f2f6f7;padding:40px 16px">
  <tr><td align="center">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
      <tr><td style="background:linear-gradient(135deg,#07474F,#0C6E77);padding:28px 32px">
        <p style="margin:0;color:#8FE3EC;font-size:11px;letter-spacing:.12em;text-transform:uppercase;font-weight:700">KassifyPay</p>
      </td></tr>
      <tr><td style="padding:36px 32px 28px">
        <p style="margin:0 0 8px;font-size:22px;font-weight:700;color:#08191F">Hi ${escHtml(name)},</p>
        <p style="margin:0 0 28px;font-size:15px;color:#666;line-height:1.6">Here is your verification code. It expires in <strong>15 minutes</strong>.</p>
        <div style="background:#eef6f7;border-radius:14px;padding:28px;text-align:center;margin-bottom:28px">
          <span style="font-family:'Courier New',monospace;font-size:40px;font-weight:800;letter-spacing:14px;color:#07474F">${otp}</span>
        </div>
        <p style="margin:0;font-size:13px;color:#999;line-height:1.6">Do not share this code with anyone. KassifyPay staff will never ask for it.</p>
      </td></tr>
      <tr><td style="padding:20px 32px;border-top:1px solid #e6f0f1">
        <p style="margin:0;font-size:12px;color:#bbb">© KassifyPay</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`,
    text: `Hi ${name},\n\nYour KassifyPay verification code is:\n\n${otp}\n\nThis code expires in 15 minutes. Do not share it with anyone.\n\n— KassifyPay`,
  });
}

/* ─── KYC approved ─── */
async function sendKycApproved(to, businessName) {
  const name = escHtml(businessName || 'there');
  await sendEmail({
    to,
    subject: '✓ Your KassifyPay account has been verified',
    html: `
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f2f6f7;font-family:'Helvetica Neue',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f2f6f7;padding:40px 16px">
  <tr><td align="center">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
      <tr><td style="background:linear-gradient(135deg,#0f5c3a,#1A9B6E);padding:28px 32px">
        <p style="margin:0;color:rgba(255,255,255,.7);font-size:11px;letter-spacing:.12em;text-transform:uppercase;font-weight:700">KassifyPay</p>
      </td></tr>
      <tr><td style="padding:36px 32px 28px">
        <div style="width:56px;height:56px;border-radius:50%;background:#e8f8f1;display:flex;align-items:center;justify-content:center;margin-bottom:22px">
          <span style="font-size:26px">✓</span>
        </div>
        <p style="margin:0 0 8px;font-size:22px;font-weight:700;color:#08191F">Hi ${name},</p>
        <p style="margin:0 0 20px;font-size:15px;color:#666;line-height:1.6">Great news — your <strong>${name}</strong> account on KassifyPay has been <strong style="color:#1A9B6E">verified</strong>. You can now accept live payments from your customers.</p>
        <a href="${BASE_URL}/dashboard" style="display:inline-block;background:#1A9B6E;color:#fff;font-weight:700;font-size:14px;padding:13px 28px;border-radius:10px;text-decoration:none;margin-bottom:24px">Go to dashboard →</a>
        <p style="margin:0;font-size:13px;color:#999;line-height:1.6">If you have any questions, reply to this email and we'll help you out.</p>
      </td></tr>
      <tr><td style="padding:20px 32px;border-top:1px solid #e6f0f1">
        <p style="margin:0;font-size:12px;color:#bbb">© KassifyPay</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`,
    text: `Hi ${businessName || 'there'},\n\nYour KassifyPay account has been verified! You can now accept live payments.\n\nGo to your dashboard: ${BASE_URL}/dashboard\n\n— KassifyPay`,
  });
}

/* ─── KYC rejected ─── */
async function sendKycRejected(to, businessName, reason) {
  const name = escHtml(businessName || 'there');
  const why  = escHtml(reason || 'Your submission did not meet our requirements.');
  await sendEmail({
    to,
    subject: 'Action required: KassifyPay account verification',
    html: `
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f2f6f7;font-family:'Helvetica Neue',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f2f6f7;padding:40px 16px">
  <tr><td align="center">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
      <tr><td style="background:linear-gradient(135deg,#07474F,#0C6E77);padding:28px 32px">
        <p style="margin:0;color:#8FE3EC;font-size:11px;letter-spacing:.12em;text-transform:uppercase;font-weight:700">KassifyPay</p>
      </td></tr>
      <tr><td style="padding:36px 32px 28px">
        <p style="margin:0 0 8px;font-size:22px;font-weight:700;color:#08191F">Hi ${name},</p>
        <p style="margin:0 0 16px;font-size:15px;color:#666;line-height:1.6">We were unable to verify your account at this time. Here is the reason:</p>
        <div style="background:#fff5f5;border-left:4px solid #EF6A4C;border-radius:6px;padding:16px 18px;margin-bottom:24px">
          <p style="margin:0;font-size:14px;color:#333;line-height:1.6">${why}</p>
        </div>
        <p style="margin:0 0 24px;font-size:15px;color:#666;line-height:1.6">Please update your submission and try again from your dashboard.</p>
        <a href="${BASE_URL}/dashboard" style="display:inline-block;background:#0C6E77;color:#fff;font-weight:700;font-size:14px;padding:13px 28px;border-radius:10px;text-decoration:none;margin-bottom:24px">Resubmit documents →</a>
        <p style="margin:0;font-size:13px;color:#999;line-height:1.6">If you think this is a mistake, reply to this email and we'll look into it.</p>
      </td></tr>
      <tr><td style="padding:20px 32px;border-top:1px solid #e6f0f1">
        <p style="margin:0;font-size:12px;color:#bbb">© KassifyPay</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`,
    text: `Hi ${businessName || 'there'},\n\nWe were unable to verify your account.\n\nReason: ${reason || 'Your submission did not meet our requirements.'}\n\nPlease resubmit your documents: ${BASE_URL}/dashboard\n\n— KassifyPay`,
  });
}

/* ─── Pending bank transfer alert (to admin) ─── */
async function sendPendingTransferAlert(adminEmail, { reference, amount, currency, merchantName }) {
  const SYMS = { GHS: '₵', NGN: '₦', USD: '$', EUR: '€', GBP: '£', KES: 'KSh', ZAR: 'R' };
  const formatted = (SYMS[currency] || (currency + ' ')) + (amount / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const ref = escHtml(reference);
  const merch = escHtml(merchantName);
  await sendEmail({
    to: adminEmail,
    subject: `New bank transfer pending — ${formatted}`,
    html: `
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f2f6f7;font-family:'Helvetica Neue',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f2f6f7;padding:40px 16px">
  <tr><td align="center">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
      <tr><td style="background:linear-gradient(135deg,#07474F,#0C6E77);padding:28px 32px">
        <p style="margin:0;color:#8FE3EC;font-size:11px;letter-spacing:.12em;text-transform:uppercase;font-weight:700">KassifyPay</p>
      </td></tr>
      <tr><td style="padding:36px 32px 28px">
        <p style="margin:0 0 6px;font-size:22px;font-weight:700;color:#08191F">Bank transfer pending</p>
        <p style="margin:0 0 24px;font-size:15px;color:#666;line-height:1.6">A customer has viewed your bank account details and is about to make a transfer. Check your bank when the money arrives, then mark this payment as paid.</p>
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f7f8;border-radius:12px;padding:20px;margin-bottom:24px">
          <tr><td style="padding:6px 0;font-size:13px;color:#888;width:120px">Amount</td><td style="padding:6px 0;font-size:16px;font-weight:800;color:#07474F;font-family:'Courier New',monospace">${formatted}</td></tr>
          <tr><td style="padding:6px 0;font-size:13px;color:#888">Merchant</td><td style="padding:6px 0;font-size:14px;color:#08191F">${merch}</td></tr>
          <tr><td style="padding:6px 0;font-size:13px;color:#888">Reference</td><td style="padding:6px 0;font-size:13px;color:#08191F;font-family:'Courier New',monospace">${ref}</td></tr>
        </table>
        <p style="margin:0 0 20px;font-size:13.5px;color:#666">The customer was told to use <strong>${ref}</strong> as their payment narration.</p>
        <a href="${BASE_URL}/admin" style="display:inline-block;background:#0C6E77;color:#fff;font-weight:700;font-size:14px;padding:13px 28px;border-radius:10px;text-decoration:none">Go to admin → Mark as paid</a>
      </td></tr>
      <tr><td style="padding:20px 32px;border-top:1px solid #e6f0f1">
        <p style="margin:0;font-size:12px;color:#bbb">© KassifyPay</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`,
    text: `Bank transfer pending\n\nAmount: ${formatted}\nMerchant: ${merchantName}\nReference: ${reference}\n\nThe customer was told to use "${reference}" as their payment narration. Check your bank, then log in to mark it paid:\n${BASE_URL}/admin\n\n— KassifyPay`,
  });
}

/* ─── Deposit success alert (to admin) ─── */
async function sendDepositAlert(adminEmail, { reference, amount, currency, merchantName, customerEmail, payerName, method }) {
  const SYMS = { GHS: '₵', NGN: '₦', USD: '$', EUR: '€', GBP: '£', KES: 'KSh', ZAR: 'R' };
  const formatted = (SYMS[currency] || (currency + ' ')) + (amount / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const METHOD_LABELS = { card: 'Card', mobile_money: 'Mobile money', bank_transfer: 'Bank transfer', ussd: 'USSD', bank: 'Bank transfer', transfer: 'Bank transfer' };
  const methodLabel = METHOD_LABELS[method] || method || 'Unknown';
  const ref = escHtml(reference);
  const merch = escHtml(merchantName);
  const custEmail = escHtml(customerEmail || '—');
  const payer = payerName ? escHtml(payerName) : null;
  await sendEmail({
    to: adminEmail,
    subject: `💰 Payment received — ${formatted}`,
    html: `
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f2f6f7;font-family:'Helvetica Neue',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f2f6f7;padding:40px 16px">
  <tr><td align="center">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
      <tr><td style="background:linear-gradient(135deg,#0f5c3a,#1A9B6E);padding:28px 32px">
        <p style="margin:0;color:rgba(255,255,255,.7);font-size:11px;letter-spacing:.12em;text-transform:uppercase;font-weight:700">KassifyPay</p>
      </td></tr>
      <tr><td style="padding:36px 32px 28px">
        <div style="width:52px;height:52px;border-radius:50%;background:#e8f8f1;display:flex;align-items:center;justify-content:center;margin-bottom:20px">
          <span style="font-size:24px">✓</span>
        </div>
        <p style="margin:0 0 4px;font-size:13px;font-weight:600;color:#1A9B6E;text-transform:uppercase;letter-spacing:.08em">Payment confirmed</p>
        <p style="margin:0 0 24px;font-size:32px;font-weight:800;color:#08191F;letter-spacing:-.5px">${formatted}</p>
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f7f8;border-radius:12px;padding:20px;margin-bottom:24px">
          <tr><td style="padding:6px 0;font-size:13px;color:#888;width:130px">Merchant</td><td style="padding:6px 0;font-size:14px;color:#08191F;font-weight:600">${merch}</td></tr>
          <tr><td style="padding:6px 0;font-size:13px;color:#888">Customer</td><td style="padding:6px 0;font-size:13px;color:#08191F">${custEmail}</td></tr>
          ${payer ? `<tr><td style="padding:6px 0;font-size:13px;color:#888">Name</td><td style="padding:6px 0;font-size:13px;color:#08191F">${payer}</td></tr>` : ''}
          <tr><td style="padding:6px 0;font-size:13px;color:#888">Method</td><td style="padding:6px 0;font-size:13px;color:#08191F">${escHtml(methodLabel)}</td></tr>
          <tr><td style="padding:6px 0;font-size:13px;color:#888">Reference</td><td style="padding:6px 0;font-size:12px;color:#08191F;font-family:'Courier New',monospace">${ref}</td></tr>
        </table>
        <a href="${BASE_URL}/admin" style="display:inline-block;background:#1A9B6E;color:#fff;font-weight:700;font-size:14px;padding:13px 28px;border-radius:10px;text-decoration:none">View in admin →</a>
      </td></tr>
      <tr><td style="padding:20px 32px;border-top:1px solid #e6f0f1">
        <p style="margin:0;font-size:12px;color:#bbb">© KassifyPay</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`,
    text: `Payment received — ${formatted}\n\nMerchant: ${merchantName}\nCustomer: ${customerEmail || '—'}${payerName ? '\nName: ' + payerName : ''}\nMethod: ${methodLabel}\nReference: ${reference}\n\nView in admin: ${BASE_URL}/admin\n\n— KassifyPay`,
  });
}

/* ─── Payment received — to the MERCHANT ───────────────────────────────────
   sendDepositAlert above notifies the platform admins. This is the merchant's
   own copy: they are the one who has actually been paid. */
async function sendMerchantDepositNotice(to, { reference, amount, currency, businessName, payerName, method }) {
  const SYMS = { GHS: '₵', NGN: '₦', USD: '$', EUR: '€', GBP: '£', KES: 'KSh', ZAR: 'R' };
  const formatted = (SYMS[currency] || (currency + ' ')) + (amount / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const METHOD_LABELS = { card: 'Card', mobile_money: 'Mobile money', bank_transfer: 'Bank transfer', ussd: 'USSD', bank: 'Bank transfer' };
  const methodLabel = METHOD_LABELS[method] || method || 'Unknown';
  const name = escHtml(businessName || 'there');
  const payer = payerName ? escHtml(payerName) : null;
  await sendEmail({
    to,
    subject: `You've been paid ${formatted}`,
    html: `
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f2f6f7;font-family:'Helvetica Neue',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f2f6f7;padding:40px 16px">
  <tr><td align="center">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
      <tr><td style="background:linear-gradient(135deg,#0f5c3a,#1A9B6E);padding:28px 32px">
        <p style="margin:0;color:rgba(255,255,255,.7);font-size:11px;letter-spacing:.12em;text-transform:uppercase;font-weight:700">KassifyPay</p>
      </td></tr>
      <tr><td style="padding:36px 32px 28px">
        <p style="margin:0 0 4px;font-size:13px;font-weight:600;color:#1A9B6E;text-transform:uppercase;letter-spacing:.08em">Payment received</p>
        <p style="margin:0 0 6px;font-size:32px;font-weight:800;color:#08191F;letter-spacing:-.5px">${formatted}</p>
        <p style="margin:0 0 24px;font-size:15px;color:#666;line-height:1.6">Hi ${name}, a customer has just paid you. The amount has been added to your balance.</p>
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f7f8;border-radius:12px;padding:20px;margin-bottom:24px">
          ${payer ? `<tr><td style="padding:6px 0;font-size:13px;color:#888;width:120px">From</td><td style="padding:6px 0;font-size:14px;color:#08191F;font-weight:600">${payer}</td></tr>` : ''}
          <tr><td style="padding:6px 0;font-size:13px;color:#888;width:120px">Method</td><td style="padding:6px 0;font-size:13px;color:#08191F">${escHtml(methodLabel)}</td></tr>
          <tr><td style="padding:6px 0;font-size:13px;color:#888">Reference</td><td style="padding:6px 0;font-size:12px;color:#08191F;font-family:'Courier New',monospace">${escHtml(reference)}</td></tr>
        </table>
        <a href="${BASE_URL}/dashboard" style="display:inline-block;background:#1A9B6E;color:#fff;font-weight:700;font-size:14px;padding:13px 28px;border-radius:10px;text-decoration:none">View dashboard →</a>
      </td></tr>
      <tr><td style="padding:20px 32px;border-top:1px solid #e6f0f1">
        <p style="margin:0;font-size:12px;color:#bbb">© KassifyPay</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`,
    text: `Payment received — ${formatted}\n\nHi ${businessName || 'there'}, a customer has just paid you.\n${payerName ? `From: ${payerName}\n` : ''}Method: ${methodLabel}\nReference: ${reference}\n\nView your dashboard: ${BASE_URL}/dashboard\n\n— KassifyPay`,
  });
}

/* ─── Payout requested — to the ADMINS ─────────────────────────────────── */
async function sendPayoutRequestAlert(adminEmail, { payoutId, amount, currency, merchantName, method, destination, note, mode }) {
  const SYMS = { GHS: '₵', NGN: '₦', USD: '$', EUR: '€', GBP: '£', KES: 'KSh', ZAR: 'R' };
  const formatted = (SYMS[currency] || (currency + ' ')) + (amount / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  const methodLabel = method === 'mobile_money' ? 'Mobile money' : 'Bank transfer';
  await sendEmail({
    to: adminEmail,
    subject: `Payout requested — ${formatted} by ${merchantName}`,
    html: `
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f2f6f7;font-family:'Helvetica Neue',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f2f6f7;padding:40px 16px">
  <tr><td align="center">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
      <tr><td style="background:linear-gradient(135deg,#07474F,#0C6E77);padding:28px 32px">
        <p style="margin:0;color:#8FE3EC;font-size:11px;letter-spacing:.12em;text-transform:uppercase;font-weight:700">KassifyPay</p>
      </td></tr>
      <tr><td style="padding:36px 32px 28px">
        <p style="margin:0 0 4px;font-size:13px;font-weight:600;color:#0C6E77;text-transform:uppercase;letter-spacing:.08em">Payout requested${mode === 'test' ? ' · test mode' : ''}</p>
        <p style="margin:0 0 24px;font-size:32px;font-weight:800;color:#08191F;letter-spacing:-.5px">${formatted}</p>
        <table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f7f8;border-radius:12px;padding:20px;margin-bottom:24px">
          <tr><td style="padding:6px 0;font-size:13px;color:#888;width:120px">Merchant</td><td style="padding:6px 0;font-size:14px;color:#08191F;font-weight:600">${escHtml(merchantName)}</td></tr>
          <tr><td style="padding:6px 0;font-size:13px;color:#888">Method</td><td style="padding:6px 0;font-size:13px;color:#08191F">${escHtml(methodLabel)}</td></tr>
          <tr><td style="padding:6px 0;font-size:13px;color:#888">Destination</td><td style="padding:6px 0;font-size:13px;color:#08191F">${escHtml(destination || '—')}</td></tr>
          ${note ? `<tr><td style="padding:6px 0;font-size:13px;color:#888">Note</td><td style="padding:6px 0;font-size:13px;color:#08191F">${escHtml(note)}</td></tr>` : ''}
          <tr><td style="padding:6px 0;font-size:13px;color:#888">Request</td><td style="padding:6px 0;font-size:12px;color:#08191F;font-family:'Courier New',monospace">${escHtml(payoutId)}</td></tr>
        </table>
        <a href="${BASE_URL}/admin" style="display:inline-block;background:#0C6E77;color:#fff;font-weight:700;font-size:14px;padding:13px 28px;border-radius:10px;text-decoration:none">Review in admin →</a>
      </td></tr>
      <tr><td style="padding:20px 32px;border-top:1px solid #e6f0f1">
        <p style="margin:0;font-size:12px;color:#bbb">© KassifyPay</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`,
    text: `Payout requested — ${formatted}\n\nMerchant: ${merchantName}\nMethod: ${methodLabel}\nDestination: ${destination || '—'}${note ? `\nNote: ${note}` : ''}\nRequest: ${payoutId}\n\nReview: ${BASE_URL}/admin\n\n— KassifyPay`,
  });
}

/* ─── Support: merchant asked a question — to the ADMINS ─────────────────── */
async function sendSupportMessageAlert(adminEmail, { merchantName, merchantEmail, body }) {
  await sendEmail({
    to: adminEmail,
    subject: `Support request from ${merchantName}`,
    html: `
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f2f6f7;font-family:'Helvetica Neue',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f2f6f7;padding:40px 16px">
  <tr><td align="center">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
      <tr><td style="background:linear-gradient(135deg,#07474F,#0C6E77);padding:28px 32px">
        <p style="margin:0;color:#8FE3EC;font-size:11px;letter-spacing:.12em;text-transform:uppercase;font-weight:700">KassifyPay</p>
      </td></tr>
      <tr><td style="padding:36px 32px 28px">
        <p style="margin:0 0 4px;font-size:13px;font-weight:600;color:#0C6E77;text-transform:uppercase;letter-spacing:.08em">Support request</p>
        <p style="margin:0 0 6px;font-size:20px;font-weight:800;color:#08191F">${escHtml(merchantName)}</p>
        <p style="margin:0 0 20px;font-size:13px;color:#888;font-family:'Courier New',monospace">${escHtml(merchantEmail || '')}</p>
        <div style="background:#f1f7f8;border-radius:12px;padding:18px;margin-bottom:24px;font-size:14px;color:#08191F;line-height:1.6;white-space:pre-wrap">${escHtml(body)}</div>
        <a href="${BASE_URL}/admin" style="display:inline-block;background:#0C6E77;color:#fff;font-weight:700;font-size:14px;padding:13px 28px;border-radius:10px;text-decoration:none">Reply in admin →</a>
      </td></tr>
      <tr><td style="padding:20px 32px;border-top:1px solid #e6f0f1">
        <p style="margin:0;font-size:12px;color:#bbb">© KassifyPay</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`,
    text: `Support request from ${merchantName} (${merchantEmail || ''})

${body}

Reply: ${BASE_URL}/admin

— KassifyPay`,
  });
}

/* ─── Support: admin replied — to the MERCHANT ───────────────────────────── */
async function sendSupportReplyNotice(to, { businessName, body }) {
  await sendEmail({
    to,
    subject: 'KassifyPay support has replied',
    html: `
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f2f6f7;font-family:'Helvetica Neue',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f2f6f7;padding:40px 16px">
  <tr><td align="center">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)">
      <tr><td style="background:linear-gradient(135deg,#07474F,#0C6E77);padding:28px 32px">
        <p style="margin:0;color:#8FE3EC;font-size:11px;letter-spacing:.12em;text-transform:uppercase;font-weight:700">KassifyPay</p>
      </td></tr>
      <tr><td style="padding:36px 32px 28px">
        <p style="margin:0 0 8px;font-size:20px;font-weight:700;color:#08191F">Hi ${escHtml(businessName || 'there')},</p>
        <p style="margin:0 0 20px;font-size:15px;color:#666;line-height:1.6">Our support team has replied to your message:</p>
        <div style="background:#f1f7f8;border-radius:12px;padding:18px;margin-bottom:24px;font-size:14px;color:#08191F;line-height:1.6;white-space:pre-wrap">${escHtml(body)}</div>
        <a href="${BASE_URL}/dashboard" style="display:inline-block;background:#0C6E77;color:#fff;font-weight:700;font-size:14px;padding:13px 28px;border-radius:10px;text-decoration:none">Open the conversation →</a>
      </td></tr>
      <tr><td style="padding:20px 32px;border-top:1px solid #e6f0f1">
        <p style="margin:0;font-size:12px;color:#bbb">© KassifyPay</p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`,
    text: `Hi ${businessName || 'there'},

Our support team has replied:

${body}

Open the conversation: ${BASE_URL}/dashboard

— KassifyPay`,
  });
}

module.exports = { sendOtp, sendKycApproved, sendKycRejected, sendPendingTransferAlert, sendDepositAlert, sendMerchantDepositNotice, sendPayoutRequestAlert, sendSupportMessageAlert, sendSupportReplyNotice };
