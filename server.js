"use strict";

const fs = require("fs");
const path = require("path");
const express = require("express");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json({ limit: "64kb" }));

// ---------------------------------------------------------------------------
// КОНФИГ
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;

// Твои Key/IV из шифрования darkvisuals.enc (env-переменные имеют приоритет)
const AES_KEY_BASE64 =
  process.env.AES_KEY_BASE64 || "xSna3nMZn+i6qPGV4rT0GZ5EgriWF2XGpKBKHeFWPP4=";
const AES_IV_BASE64 =
  process.env.AES_IV_BASE64 || "ZuFERVewWrSKiQxrjr70Jw==";

const MOD_URL =
  process.env.MOD_URL ||
  "https://raw.githubusercontent.com/kryytoi/notwhdwnwdwdjd/main/darkvisuals.enc";

const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";

const USERS_FILE = path.join(__dirname, "users.json");

// ---------------------------------------------------------------------------
// ПОЛЬЗОВАТЕЛИ
// ---------------------------------------------------------------------------
let users = [];

function loadUsers() {
  if (process.env.USERS_JSON) {
    try {
      users = JSON.parse(process.env.USERS_JSON);
      return;
    } catch (e) {
      console.error("USERS_JSON is not valid JSON:", e.message);
    }
  }
  try {
    if (fs.existsSync(USERS_FILE)) {
      users = JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
    }
  } catch (e) {
    console.error("Failed to read users.json:", e.message);
    users = [];
  }
}

function saveUsers() {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
  } catch (e) {
    console.error("Failed to write users.json:", e.message);
  }
}

function findUser(username) {
  if (!username) return null;
  const lower = String(username).trim().toLowerCase();
  return users.find((u) => String(u.username).toLowerCase() === lower) || null;
}

// ---------------------------------------------------------------------------
// ПРОВЕРКА ЛИЦЕНЗИИ
// ---------------------------------------------------------------------------
function isExpired(expires) {
  if (!expires) return false;
  if (String(expires).toLowerCase() === "lifetime") return false;
  const t = Date.parse(expires);
  if (Number.isNaN(t)) return false;
  return t < Date.now();
}

async function verifyLicense(username, password, hwid, checkPassword) {
  const user = findUser(username);
  if (!user) return { ok: false, message: "Неверный логин или пароль!" };

  if (checkPassword) {
    const match = await bcrypt.compare(String(password || ""), user.passwordHash || "");
    if (!match) return { ok: false, message: "Неверный логин или пароль!" };
  }

  if (user.banned) return { ok: false, message: "Аккаунт заблокирован!" };

  if (isExpired(user.expires))
    return { ok: false, message: "Срок подписки истёк!" };

  const cleanHwid = String(hwid || "").trim();
  if (!cleanHwid) return { ok: false, message: "HWID не передан." };

  if (!user.hwid) {
    user.hwid = cleanHwid;
    saveUsers();
  } else if (user.hwid !== cleanHwid) {
    return { ok: false, message: "HWID не совпадает! Лицензия привязана к другому ПК." };
  }

  return { ok: true, user };
}

// ---------------------------------------------------------------------------
// /api/login
// ---------------------------------------------------------------------------
app.post("/api/login", async (req, res) => {
  try {
    const { username, password, hwid } = req.body || {};
    const result = await verifyLicense(username, password, hwid, true);

    if (!result.ok) {
      return res.json({ success: false, message: result.message });
    }

    return res.json({
      success: true,
      message: "OK",
      role: result.user.role || "User",
    });
  } catch (e) {
    console.error("/api/login error:", e);
    return res.status(500).json({ success: false, message: "Ошибка сервера." });
  }
});

// ---------------------------------------------------------------------------
// /api/mod-key
// ---------------------------------------------------------------------------
app.post("/api/mod-key", async (req, res) => {
  try {
    if (!AES_KEY_BASE64 || !AES_IV_BASE64) {
      return res.status(500).json({ error: "Ключ на сервере не настроен." });
    }

    const { login, hwid } = req.body || {};
    const result = await verifyLicense(login, null, hwid, false);

    if (!result.ok) {
      return res.status(403).json({ error: result.message });
    }

    return res.json({
      KeyBase64: AES_KEY_BASE64,
      IvBase64: AES_IV_BASE64,
      ModUrl: MOD_URL,
    });
  } catch (e) {
    console.error("/api/mod-key error:", e);
    return res.status(500).json({ error: "Ошибка сервера." });
  }
});

// ---------------------------------------------------------------------------
// АДМИНКА (заголовок x-admin-token)
// ---------------------------------------------------------------------------
function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return res.status(403).json({ error: "Admin disabled." });
  if (req.headers["x-admin-token"] !== ADMIN_TOKEN)
    return res.status(401).json({ error: "Unauthorized." });
  next();
}

app.get("/admin/users", requireAdmin, (req, res) => {
  res.json(
    users.map((u) => ({
      username: u.username,
      role: u.role,
      banned: !!u.banned,
      expires: u.expires,
      hwid: u.hwid || null,
    }))
  );
});

app.post("/admin/users", requireAdmin, (req, res) => {
  const { username, passwordHash, role, expires } = req.body || {};
  if (!username || !passwordHash)
    return res.status(400).json({ error: "username и passwordHash обязательны." });

  let user = findUser(username);
  if (user) {
    user.passwordHash = passwordHash;
    if (role) user.role = role;
    if (expires) user.expires = expires;
  } else {
    users.push({
      username: String(username).trim(),
      passwordHash,
      role: role || "User",
      banned: false,
      expires: expires || "lifetime",
      hwid: null,
    });
  }
  saveUsers();
  res.json({ ok: true });
});

app.post("/admin/ban", requireAdmin, (req, res) => {
  const { username, banned } = req.body || {};
  const user = findUser(username);
  if (!user) return res.status(404).json({ error: "Не найден." });
  user.banned = !!banned;
  saveUsers();
  res.json({ ok: true, banned: user.banned });
});

app.post("/admin/reset-hwid", requireAdmin, (req, res) => {
  const { username } = req.body || {};
  const user = findUser(username);
  if (!user) return res.status(404).json({ error: "Не найден." });
  user.hwid = null;
  saveUsers();
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
app.get("/", (req, res) => res.send("DarkVisuals server is running."));

loadUsers();
app.listen(PORT, () => {
  console.log(`DarkVisuals server listening on port ${PORT}`);
  console.log(`Loaded ${users.length} user(s).`);
});
