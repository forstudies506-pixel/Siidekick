// CampusKart student verification for discounted fest passes. DELIBERATELY VULNERABLE: part of the
// Siidekick demo. Never deploy. No real identity numbers appear in this file.
const express = require('express');

const router = express.Router();
const students = [];

router.post('/api/kyc', (req, res) => {
  const { name, college, aadhaar, panNumber, dob } = req.body;
  console.log('new student kyc', name, college, aadhaar, panNumber, dob);
  students.push({ name, college, aadhaar, panNumber, dob });
  res.json({ ok: true });
});

module.exports = { router, students };
