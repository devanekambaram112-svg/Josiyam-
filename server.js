require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const Razorpay = require('razorpay');

const app = express();
const PORT = process.env.PORT || 3000;

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Store server-side orders in memory (replace with MongoDB/Postgres in production)
const ordersStore = new Map();

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
  if (event.event === 'payment.captured') {
    const payment = event.payload.payment.entity;
    const record = ordersStore.get(payment.order_id);
    if (record) record.status = 'paid';
  }
  res.status(200).send('ok');
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/config', (req, res) => {
  res.json({
    live: Boolean(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET),
    keyId: process.env.RAZORPAY_KEY_ID || ''
  });
});

app.post('/api/create-order', async (req, res) => {
  try {
    const { pkgId, pkgTitle, amountInr, customerName } = req.body;
    const amountPaise = Math.max(100, Math.round(Number(amountInr) * 100));
    const receipt = `josiyam_${Date.now()}`;

    const order = await razorpay.orders.create({
      amount: amountPaise,
      currency: 'INR',
      receipt,
      notes: { pkgId, pkgTitle, customerName }
    });

    ordersStore.set(order.id, {
      orderId: order.id,
      pkgId,
      pkgTitle,
      amountInr,
      status: 'created'
    });

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
    return res.status(400).json({ verified: false, error: 'Missing payment fields' });
  }

  const body = `${serverOrderId}|${razorpay_payment_id}`;
  const expected = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(body)
    .digest('hex');

  const valid =
    expected.length === razorpay_signature.length &&
    crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(razorpay_signature));

  if (!valid) {
    return res.status(400).json({ verified: false, error: 'Signature verification failed' });
  }

  const record = ordersStore.get(serverOrderId);
  if (record) record.status = 'paid';

  res.json({ verified: true, paymentId: razorpay_payment_id, orderId: serverOrderId });
});

app.listen(PORT, () => {
  console.log(`Sri NavaGraha Josiyam server running on http://localhost:${PORT}`);
});
