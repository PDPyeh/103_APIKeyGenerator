const express = require("express");
const crypto = require("crypto");
const path = require("path");
const db = require("./db");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require("dotenv").config();

const app = express();
app.use(express.json());

const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// ================== Helper random API key ==================
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

function randBase62(length) {
  const buf = crypto.randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) {
    out += ALPHABET[buf[i] % ALPHABET.length];
  }
  return out;
}

function generateKey() {
  return 'sk-' + randBase62(40);
}

// ================== Middleware Auth Admin ==================
function authAdmin(req, res, next) {
  const auth = req.headers.authorization || '';
  const [type, token] = auth.split(' ');
  if (type !== 'Bearer' || !token) {
    return res.status(401).json({ message: 'No token' });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.adminId = payload.id;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

// ================== ROUTES PUBLIC ==================


app.use(express.static(path.join(__dirname, 'public')));

// POST /create  → generate API key saja (tanpa simpan DB, simpan pas /users)
app.post('/create', (req, res) => {
  const key = generateKey();
  res.json({ api_key: key });
});


app.listen(PORT, () => {
  console.log('Server running on http://localhost:' + PORT);
});
