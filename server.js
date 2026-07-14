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

const AES_KEY_BASE64 =
  process.env.AES_KEY_BASE64 || "xSna3nMZn+i6qPGV4rT0GZ5EgriWF2XGpKBKHeFWPP4=";
const AES_IV_BASE64 =
  process.env.AES_IV_BASE64 || "ZuFERVewWrSKiQxrjr70Jw==";

const MOD_URL =
  process.env.MOD_URL ||
  "https://raw.githubusercontent.com/kryytoi/notwhdwnwdwdjd/main/darkvisuals.enc";

// Путь, по которому открывается админка. ПОМЕНЯЙ на что-то секретное!
const PANEL_PATH = process.env.PANEL_PATH || "/panel";

const USERS_FILE = path.join(__dirname, "users.json");

// ---------------------------------------------------------------------------
// ПОЛЬЗОВАТЕЛИ
// ---------------------------------------------------------------------------
let users = [];

function loadUsers() {
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

function isExpired(user) {
  const exp = user.expiresAt || user.expires;
  if (!exp) return false;
  if (String(exp).toLowerCase() === "lifetime") return false;
  const t = Date.parse(exp);
  if (Number.isNaN(t)) return false;
  return t < Date.now();
}

// ---------------------------------------------------------------------------
// ПРОВЕРКА ЛИЦЕНЗИИ (для лаунчера)
// ---------------------------------------------------------------------------
async function verifyLicense(username, password, hwid, checkPassword) {
  const user = findUser(username);
  if (!user) return { ok: false, message: "Неверный логин или пароль!" };

  if (checkPassword) {
    const match = await bcrypt.compare(String(password || ""), user.passwordHash || "");
    if (!match) return { ok: false, message: "Неверный логин или пароль!" };
  }

  if (user.banned) return { ok: false, message: "Аккаунт заблокирован!" };
  if (isExpired(user)) return { ok: false, message: "Срок подписки истёк!" };

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

app.post("/api/login", async (req, res) => {
  try {
    const { username, password, hwid } = req.body || {};
    const result = await verifyLicense(username, password, hwid, true);
    if (!result.ok) return res.json({ success: false, message: result.message });
    return res.json({ success: true, message: "OK", role: result.user.role || "User" });
  } catch (e) {
    console.error("/api/login error:", e);
    return res.status(500).json({ success: false, message: "Ошибка сервера." });
  }
});

app.post("/api/mod-key", async (req, res) => {
  try {
    const { login, hwid } = req.body || {};
    const result = await verifyLicense(login, null, hwid, false);
    if (!result.ok) return res.status(403).json({ error: result.message });
    return res.json({ KeyBase64: AES_KEY_BASE64, IvBase64: AES_IV_BASE64, ModUrl: MOD_URL });
  } catch (e) {
    console.error("/api/mod-key error:", e);
    return res.status(500).json({ error: "Ошибка сервера." });
  }
});

// ---------------------------------------------------------------------------
// АДМИН-API (под index.html)
// ---------------------------------------------------------------------------
app.get("/api/admin/users", (req, res) => {
  res.json({
    users: users.map((u) => ({
      username: u.username,
      hwid: u.hwid || null,
      banned: !!u.banned,
      expiresAt: u.expiresAt || null,
      role: u.role || "User",
    })),
  });
});

app.post("/api/admin/create", async (req, res) => {
  const { username, password, days } = req.body || {};
  const name = String(username || "").trim();
  if (!name || !password)
    return res.json({ success: false, message: "Логин и пароль обязательны." });
  if (findUser(name))
    return res.json({ success: false, message: "Такой логин уже существует." });

  const d = parseInt(days, 10);
  const expiresAt =
    d > 0 ? new Date(Date.now() + d * 24 * 60 * 60 * 1000).toISOString() : null;

  users.push({
    username: name,
    passwordHash: await bcrypt.hash(String(password), 10),
    role: "User",
    banned: false,
    expiresAt,
    hwid: null,
  });
  saveUsers();
  res.json({ success: true });
});

app.post("/api/admin/reset-hwid", (req, res) => {
  const user = findUser(req.body?.username);
  if (!user) return res.json({ success: false, message: "Пользователь не найден." });
  user.hwid = null;
  saveUsers();
  res.json({ success: true });
});

app.post("/api/admin/toggle-ban", (req, res) => {
  const user = findUser(req.body?.username);
  if (!user) return res.json({ success: false, message: "Пользователь не найден." });
  user.banned = !!req.body.banned;
  saveUsers();
  res.json({ success: true });
});

app.post("/api/admin/delete", (req, res) => {
  const name = String(req.body?.username || "").trim().toLowerCase();
  const before = users.length;
  users = users.filter((u) => String(u.username).toLowerCase() !== name);
  if (users.length === before)
    return res.json({ success: false, message: "Пользователь не найден." });
  saveUsers();
  res.json({ success: true });
});

app.post("/api/admin/set-days", (req, res) => {
  const user = findUser(req.body?.username);
  if (!user) return res.json({ success: false, message: "Пользователь не найден." });
  const d = parseInt(req.body?.days, 10);
  user.expiresAt = d > 0 ? new Date(Date.now() + d * 24 * 60 * 60 * 1000).toISOString() : null;
  saveUsers();
  res.json({ success: true });
});

// ---------------------------------------------------------------------------
// АДМИНКА (HTML)
// ---------------------------------------------------------------------------
app.get(PANEL_PATH, (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/", (req, res) => res.send("DarkVisuals server is running."));

loadUsers();
app.listen(PORT, () => {
  console.log(`DarkVisuals server listening on port ${PORT}`);
  console.log(`Admin panel: ${PANEL_PATH}`);
  console.log(`Loaded ${users.length} user(s).`);
});
