const test = require('node:test');
const assert = require('node:assert/strict');

const app = require('../server.js');

async function request(path, options = {}) {
  const server = app.listen(0);
  try {
    const { port } = server.address();
    const res = await fetch(`http://127.0.0.1:${port}${path}`, options);
    const body = await res.json().catch(() => null);
    return { status: res.status, body, headers: res.headers };
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('GET / returns 200', async () => {
  const res = await request('/');
  assert.strictEqual(res.status, 200);
});

test('POST /login returns 200 for a seeded user', async () => {
  const res = await request('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'aarya@campus.edu', password: 'password123' })
  });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.ok, true);
  assert.strictEqual(res.body.user.name, 'Aarya Patel');
});

test('POST /login returns 401 for a bad password', async () => {
  const res = await request('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'aarya@campus.edu', password: 'wrong-password' })
  });
  assert.strictEqual(res.status, 401);
});

test('GET /api/products?q=tee returns an array', async () => {
  const res = await request('/api/products?q=tee');
  assert.strictEqual(res.status, 200);
  assert.ok(Array.isArray(res.body));
  assert.ok(res.body.length > 0);
});
