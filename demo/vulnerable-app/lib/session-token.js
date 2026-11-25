// Session tokens for the planned mobile app. Not loaded by server.js; demo flaw only.
const jwt = require("jsonwebtoken");

const SECRET = process.env.JWT_SECRET || "campuskart-dev";

function issue(user) {
  return jwt.sign({ sub: user.id, role: user.role }, SECRET, { expiresIn: "7d" });
}

function check(token) {
  return jwt.verify(token, SECRET, { ignoreExpiration: true });
}

module.exports = { issue, check };
