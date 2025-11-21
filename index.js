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


app.listen(PORT, () => {
  console.log('Server running on http://localhost:' + PORT);
});
