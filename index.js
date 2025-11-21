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

// POST /users → simpan user + api_key ke DB
app.post('/users', async (req, res) => {
  const { first_name, last_name, email, api_key } = req.body;

  if (!first_name || !last_name || !email || !api_key) {
    return res.status(400).json({ message: 'Field wajib diisi' });
  }

  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    // insert user
    const [userResult] = await conn.execute(
      'INSERT INTO users (first_name, last_name, email) VALUES (?,?,?)',
      [first_name, last_name, email]
    );
    const userId = userResult.insertId;

    // masa berlaku: 30 hari dari sekarang
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    await conn.execute(
      'INSERT INTO api_keys (user_id, api_key, expires_at) VALUES (?,?,?)',
      [userId, api_key, expiresAt]
    );

    await conn.commit();
    res.status(201).json({ message: 'User & API key tersimpan', user_id: userId });
  } catch (err) {
    await conn.rollback();
    console.error(err);
    res.status(500).json({ message: 'Gagal simpan user', error: err.message });
  } finally {
    conn.release();
  }
});

// POST /checkapi → cek valid / out_of_date
app.post('/checkapi', async (req, res) => {
  const { api_key } = req.body;
  if (!api_key) return res.status(400).json({ message: 'api_key wajib' });

  try {
    const [rows] = await db.execute(
      'SELECT id, status, expires_at FROM api_keys WHERE api_key = ?',
      [api_key]
    );

    if (rows.length === 0) {
      return res.status(404).json({ valid: false, message: 'Key tidak ditemukan' });
    }

    const keyRow = rows[0];
    const now = new Date();
    const exp = new Date(keyRow.expires_at);

    if (keyRow.status === 'revoked') {
      return res.json({ valid: false, message: 'Key revoked' });
    }

    if (exp < now) {
      // update jadi out_of_date kalau expired
      await db.execute(
        'UPDATE api_keys SET status = ? WHERE id = ?',
        ['out_of_date', keyRow.id]
      );
      return res.json({ valid: false, message: 'Key out of date' });
    }

    return res.json({ valid: true, message: 'Key masih aktif' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ valid: false, message: 'Error server' });
  }
});

// ================== ROUTES ADMIN AUTH ==================

// POST /admin/register
app.post('/admin/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: 'Email & password wajib' });

  try {
    const hash = await bcrypt.hash(password, 10);
    await db.execute(
      'INSERT INTO admins (email, password_hash) VALUES (?,?)',
      [email, hash]
    );
    res.status(201).json({ message: 'Admin berhasil register' });
  } catch (err) {
    console.error(err);
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ message: 'Email sudah terdaftar' });
    }
    res.status(500).json({ message: 'Gagal register admin' });
  }
});

// POST /admin/login
app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: 'Email & password wajib' });

  try {
    const [rows] = await db.execute(
      'SELECT * FROM admins WHERE email = ?',
      [email]
    );
    if (rows.length === 0)
      return res.status(401).json({ message: 'Email / password salah' });

    const admin = rows[0];
    const match = await bcrypt.compare(password, admin.password_hash);
    if (!match)
      return res.status(401).json({ message: 'Email / password salah' });

    const token = jwt.sign({ id: admin.id }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Gagal login' });
  }
});

// ================== ROUTES ADMIN PROTECTED ==================

// GET /admin/users → list user + api key + status + expires_at
app.get('/admin/users', authAdmin, async (req, res) => {
  try {
    const [rows] = await db.execute(`
      SELECT u.id,
             u.first_name,
             u.last_name,
             u.email,
             k.api_key,
             k.status,
             k.expires_at
      FROM users u
      LEFT JOIN api_keys k ON k.user_id = u.id
      ORDER BY u.created_at DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Gagal ambil data user' });
  }
});

app.listen(PORT, () => {
  console.log('Server running on http://localhost:' + PORT);
});
