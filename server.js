require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const Razorpay = require('razorpay');

const app = express();
const PORT = process.env.PORT || 3000;

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_placeholder',
  key_secret: process.env.RAZORPAY_KEY_SECRET || 'secret_placeholder'
});

const ordersStore = new Map();
const otpStore = new Map();
const usersStore = new Map();

// Webhook route MUST use express.raw before express.json
app.post('/api/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
  if (!secret) return res.status(200).send('ok');

  const signature = req.headers['x-razorpay-signature'];
  const expected = crypto.createHmac('sha256', secret).update(req.body).digest('hex');
  if (!signature || signature !== expected) {
    return res.status(400).send('Invalid webhook signature');
  }

  const event = JSON.parse(req.body.toString('utf8'));
  if (event.event === 'payment.captured' || event.event === 'subscription.charged') {
    const entity = event.payload.payment ? event.payload.payment.entity : null;
    if (entity && entity.order_id && ordersStore.has(entity.order_id)) {
      ordersStore.get(entity.order_id).status = 'paid';
    }
  }
  res.status(200).send('ok');
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/config', (req, res) => {
  res.json({
    live: Boolean(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET),
    hasPlan: Boolean(process.env.RAZORPAY_PLAN_ID),
    hasAi: Boolean(process.env.GEMINI_API_KEY),
    hasSms: Boolean(process.env.FAST2SMS_API_KEY),
    keyId: process.env.RAZORPAY_KEY_ID || ''
  });
});

// SMS OTP Login Endpoints
app.post('/api/send-otp', async (req, res) => {
  try {
    const cleanPhone = String(req.body.phone || '').replace(/\D/g, '').slice(-10);
    if (cleanPhone.length !== 10) {
      return res.status(400).json({ error: 'Enter a valid 10-digit mobile number' });
    }

    const code = String(Math.floor(100000 + Math.random() * 900000));
    otpStore.set(cleanPhone, { code, expiresAt: Date.now() + 5 * 60 * 1000 });

    const smsKey = process.env.FAST2SMS_API_KEY;
    if (smsKey) {
      const smsRes = await fetch('https://www.fast2sms.com/dev/bulkV2', {
        method: 'POST',
        headers: {
          authorization: smsKey,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          route: 'otp',
          variables_values: code,
          numbers: cleanPhone
        })
      });
      if (!smsRes.ok) {
        return res.status(502).json({ error: 'SMS gateway failed' });
      }
      return res.json({ sent: true, mode: 'live_sms' });
    }

    // Fallback test OTP when FAST2SMS_API_KEY is not configured yet
    return res.json({ sent: true, mode: 'test', demoOtp: code });
  } catch (err) {
    console.error('Send OTP error:', err);
    res.status(500).json({ error: 'Unable to send OTP' });
  }
});

app.post('/api/verify-otp', (req, res) => {
  const cleanPhone = String(req.body.phone || '').replace(/\D/g, '').slice(-10);
  const code = String(req.body.otp || '').trim();
  const record = otpStore.get(cleanPhone);

  if (!record || Date.now() > record.expiresAt || record.code !== code) {
    return res.status(400).json({ verified: false, error: 'Invalid or expired OTP' });
  }

  otpStore.delete(cleanPhone);
  const existing = usersStore.get(cleanPhone) || { phone: cleanPhone, createdAt: Date.now(), vip: false };
  usersStore.set(cleanPhone, existing);
  const token = crypto.randomBytes(16).toString('hex');
  res.json({ verified: true, token, user: existing });
});

// One-time order (Jathagam / Porutham / Live Call)
app.post('/api/create-order', async (req, res) => {
  try {
    const { pkgId, pkgTitle, amountInr, customerName, phone } = req.body;
    const amountPaise = Math.max(100, Math.round(Number(amountInr) * 100));
    const order = await razorpay.orders.create({
      amount: amountPaise,
      currency: 'INR',
      receipt: `josiyam_${Date.now()}`,
      notes: { pkgId, pkgTitle, customerName, phone: phone || '' }
    });
    ordersStore.set(order.id, { orderId: order.id, pkgId, pkgTitle, amountInr, phone, status: 'created' });
    res.json({
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      keyId: process.env.RAZORPAY_KEY_ID
    });
  } catch (err) {
    console.error('Create order error:', err);
    res.status(500).json({ error: 'Unable to create Razorpay order' });
  }
});

app.post('/api/verify-payment', (req, res) => {
  const { serverOrderId, razorpay_payment_id, razorpay_signature } = req.body;
  if (!serverOrderId || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ verified: false });
  }
  const expected = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(`${serverOrderId}|${razorpay_payment_id}`)
    .digest('hex');

  const valid =
    expected.length === razorpay_signature.length &&
    crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(razorpay_signature));

  if (!valid) return res.status(400).json({ verified: false });
  if (ordersStore.has(serverOrderId)) ordersStore.get(serverOrderId).status = 'paid';
  res.json({ verified: true, paymentId: razorpay_payment_id });
});

// AutoPay Subscription: 1-Day Free Trial -> ₹59 Recurring
app.post('/api/create-subscription', async (req, res) => {
  try {
    if (!process.env.RAZORPAY_PLAN_ID) {
      return res.status(400).json({ error: 'RAZORPAY_PLAN_ID not configured' });
    }
    const { customerName, phone } = req.body;
    const startAt = Math.floor(Date.now() / 1000) + 86400; // +24 hours (1-Day Free Trial)
    const sub = await razorpay.subscriptions.create({
      plan_id: process.env.RAZORPAY_PLAN_ID,
      total_count: 52,
      quantity: 1,
      customer_notify: 1,
      start_at: startAt,
      notes: { customerName: customerName || 'Guest', phone: phone || '', trial: '1_day_free_then_59_inr' }
    });
    res.json({
      subscriptionId: sub.id,
      keyId: process.env.RAZORPAY_KEY_ID,
      startAt
    });
  } catch (err) {
    console.error('Subscription error:', err);
    res.status(500).json({ error: 'Unable to create Razorpay subscription' });
  }
});

app.post('/api/verify-subscription', (req, res) => {
  const { subscriptionId, razorpay_payment_id, razorpay_signature, phone } = req.body;
  if (!subscriptionId || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ verified: false });
  }
  const expected = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(`${razorpay_payment_id}|${subscriptionId}`)
    .digest('hex');

  const valid =
    expected.length === razorpay_signature.length &&
    crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(razorpay_signature));

  if (!valid) return res.status(400).json({ verified: false });
  if (phone && usersStore.has(phone)) usersStore.get(phone).vip = true;
  res.json({ verified: true, subscriptionId, paymentId: razorpay_payment_id });
});

// Real Gemini AI Astrologer Chat Endpoint
app.post('/api/astro-chat', async (req, res) => {
  try {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) return res.status(503).json({ error: 'GEMINI_API_KEY not set' });

    const { astrologerName, astrologerRole, userName, rasi, star, question } = req.body;
    const prompt = `You are ${astrologerName} (${astrologerRole}), a warm, respectful South Indian Vedic astrologer.
User Name: ${userName || 'Friend'}
Rasi: ${rasi}
Nakshatram: ${star}
User Question: ${question}

Reply in 2 to 4 concise sentences in natural Tanglish (matching the user's language if English/Tamil), giving thoughtful Vedic astrology guidance and one simple temple/lamp pariharam.`;

    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${encodeURIComponent(apiKey)}`;
    const aiRes = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
    });
    const data = await aiRes.json();
    const reply = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!reply) return res.status(502).json({ error: 'Empty AI response' });
    res.json({ reply });
  } catch (err) {
    console.error('AI chat error:', err);
    res.status(500).json({ error: 'AI chat failed' });
  }
});

app.listen(PORT, () => {
  console.log(`Sri NavaGraha Josiyam server running on http://localhost:${PORT}`);
});
