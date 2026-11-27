// CampusKart phone login with an SMS OTP. DELIBERATELY VULNERABLE: part of the Siidekick demo. Never deploy.
// The key below is a fake demo value.
const express = require('express');

const router = express.Router();

const MSG91_AUTHKEY = '362850DemoKeyNotReal91x';
const pending = new Map();

router.post('/api/otp/send', (req, res) => {
  const { phone } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000);
  pending.set(phone, otp);
  console.log('otp for', phone, otp);
  res.json({ sent: true, otp });
});

router.post('/api/otp/verify', (req, res) => {
  const { phone, code } = req.body;
  res.json({ ok: pending.get(phone) === Number(code) });
});

module.exports = { router, MSG91_AUTHKEY };
