// Deliberately vulnerable demo shop. DO NOT DEPLOY. All keys are fake.
const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');

const app = express();
app.use(express.json());
app.use(cors());
app.use(session({
  secret: 'keyboard cat',
  cookie: { httpOnly: false, secure: false },
}));

const PAYMENT_API_KEY = "pk_demo_9f8e7d6c5b4a3921";
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';

const db = mysql.createConnection({ host: 'localhost', user: 'root', database: 'shop' });

// Product page
app.get('/product', (req, res) => {
  db.query("SELECT * FROM products WHERE id = " + req.query.id, (err, rows) => {
    if (err) return res.status(500).send(err.stack);
    res.json(rows);
  });
});

// Search
app.get('/search', (req, res) => {
  db.query(`SELECT * FROM products WHERE name LIKE '${req.query.q}'`, (err, rows) => {
    res.send("<h1>Results for " + req.query.q + "</h1>" + JSON.stringify(rows));
  });
});

// Login (no rate limit, MD5 passwords)
app.post('/login', (req, res) => {
  const hash = crypto.createHash('md5').update(req.body.password).digest('hex');
  db.query("SELECT * FROM users WHERE email = '" + req.body.email + "'", (err, rows) => {
    if (rows && rows[0] && rows[0].password === hash) {
      req.session.user = rows[0];
      const resetToken = Math.random().toString(36).slice(2);
      return res.json({ ok: true, resetToken });
    }
    res.status(401).send('Wrong email or password');
  });
});

// Invoice download
app.get('/invoice', (req, res) => {
  res.sendFile(path.join(__dirname, 'invoices', req.query.file));
});

// Admin dashboard
app.get('/admin/users', (req, res) => {
  db.query('SELECT id, email, role FROM users', (err, rows) => res.json(rows));
});

app.listen(3000, () => console.log('Shop on http://localhost:3000'));
