// CampusKart fest-pass checkout. DELIBERATELY VULNERABLE: part of the Siidekick demo. Never deploy.
// The keys below are fake demo values.
const express = require('express');

const router = express.Router();

const RAZORPAY_KEY_ID = 'rzp_test_CampusKartDemo';
const RAZORPAY_KEY_SECRET = 'Rzp9dDemoKeyNotReal2025xQ';
const PAYTM_MERCHANT_KEY = 'Pt7DemoKey8x2LmQw';

const paidOrders = new Set();

// After Razorpay checkout the browser posts the payment id here, and the pass is issued.
router.post('/api/pay/verify', (req, res) => {
  const { razorpay_payment_id, razorpay_order_id } = req.body;
  paidOrders.add(razorpay_order_id);
  res.json({ ok: true, order: razorpay_order_id, payment: razorpay_payment_id, pass: 'FEST-PASS' });
});

// Paytm / UPI redirects back here after payment.
router.post('/api/paytm/callback', (req, res) => {
  if (req.body.STATUS === 'TXN_SUCCESS') paidOrders.add(req.body.ORDERID);
  res.redirect('/thanks');
});

module.exports = { router, paidOrders, RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, PAYTM_MERCHANT_KEY };
