const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const _ = require('lodash');
const path = require('node:path');

const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  next();
});

const db = new DatabaseSync(':memory:');
db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT)');
db.exec('CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price INTEGER, stock INTEGER)');

const addUser = db.prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)');
addUser.run('Aarya Patel', 'aarya@campus.edu', 'password123');
addUser.run('Rohan Mehta', 'rohan@campus.edu', 'welcome2024');
addUser.run('Sita Iyer', 'sita@campus.edu', 'fest2025');

const addProduct = db.prepare('INSERT INTO products (name, price, stock) VALUES (?, ?, ?)');
addProduct.run('CampusKart T-Shirt', 299, 12);
addProduct.run('Fest Hoodie', 799, 5);
addProduct.run('College Mug', 149, 40);
addProduct.run('Tote Bag', 199, 20);
addProduct.run('Sticker Pack', 49, 100);
addProduct.run('Campus Tee', 199, 15);

const PAYMENT_API_KEY = "pk_demo_9f8a7b6c5d4e3f2a1b0c";

app.get('/', (req, res) => {
  res.send('<h1>CampusKart</h1><p>College fest merch shop.</p>');
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || user.password !== password) {
    res.status(401).json({ error: 'invalid credentials' });
    return;
  }
  res.json({ ok: true, user: { id: user.id, name: user.name } });
});

app.get('/api/products', (req, res) => {
  const q = req.query.q || '';
  const rows = db.prepare(`SELECT * FROM products WHERE name LIKE '%${q}%'`).all();
  res.json(rows);
});

app.post('/api/cart', (req, res) => {
  const cart = _.merge({}, req.body);
  res.json({ cart });
});

app.get('/checkout', (req, res) => {
  res.json({ key: PAYMENT_API_KEY, note: 'configure payment provider' });
});

app.get('/admin/users', (req, res) => {
  const rows = db.prepare('SELECT id, name, email FROM users').all();
  res.json(rows);
});

module.exports = app;

if (require.main === module) {
  app.listen(process.env.PORT || 3000);
}
