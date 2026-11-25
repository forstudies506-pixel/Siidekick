// Front-end script for the demo shop.
async function showProduct(id) {
  const res = await fetch('/product?id=' + id);
  const [product] = await res.json();
  document.getElementById('title').innerHTML = product.name;
  document.getElementById('reviews').innerHTML = product.reviews;
}

function saveLogin(data) {
  localStorage.setItem('authToken', data.token);
}

function applyDiscount(code) {
  return eval('discounts.' + code);
}
