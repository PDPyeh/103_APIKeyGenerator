const express = require("express");
const crypto = require("crypto");
const path = require("path");
const pool = require("./db");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function generateApiKey(length = 40) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const buf = crypto.randomBytes(length);
  let key = "";
  for (let i = 0; i < buf.length; i++) {
    key += chars[buf[i] % chars.length];
  }
  return `sk-${key}`;
}

// ✅ CREATE API KEY
app.post("/create", async (req, res) => {
  try {
    const key = generateApiKey(40);

    await pool.execute(
      "INSERT INTO api_keys (api_key) VALUES (?)",
      [key]
    );

    return res.json({ api_key: key });
  } catch (err) {
    console.error("DB Insert Error:", err);
    return res.status(500).json({ message: "Failed to store api key" });
  }
});

// ✅ CHECK API KEY
app.post("/checkapi", async (req, res) => {
  try {
    const { api_key } = req.body;

    if (!api_key) {
      return res.status(400).json({ valid: false, message: "No api_key provided" });
    }

    const [rows] = await pool.execute(
      "SELECT id, created_at FROM api_keys WHERE api_key = ? LIMIT 1",
      [api_key]
    );

    if (!rows.length) {
      return res.status(404).json({ valid: false, message: "API key not found" });
    }

    return res.json({ valid: true, data: rows[0] });
  } catch (err) {
    console.error("Check Error:", err);
    return res.status(500).json({ valid: false, message: "DB error" });
  }
});

// ✅ Root serve UI
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/keys", async (_req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT id, api_key, created_at FROM api_keys ORDER BY id DESC"
    );
    res.json({ count: rows.length, data: rows });
  } catch (err) {
    console.error("💥 /keys error:", err.sqlMessage || err.message);
    res.status(500).json({ message: "Failed to fetch keys" });
  }
});

app.listen(port, () => {
  console.log(`✅ Server running at http://localhost:${port}`);
});
