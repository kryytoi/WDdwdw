const util = require('util');
// Фикс для старой библиотеки NeDB: в новых версиях Node.js
// эти функции удалили из util, а NeDB ими пользуется.
// Без этих строк ЛЮБОЙ поиск/бан/удаление падает с ошибкой
// "util.isRegExp is not a function".
util.isDate = function (val) { return val instanceof Date; };
util.isRegExp = function (val) { return val instanceof RegExp; };
util.isArray = Array.isArray;
util.isError = function (val) { return val instanceof Error; };
util.isFunction = function (val) { return typeof val === 'function'; };
util.isString = function (val) { return typeof val === 'string'; };
util.isNumber = function (val) { return typeof val === 'number'; };
util.isObject = function (val) { return val !== null && typeof val === 'object'; };
util.isUndefined = function (val) { return val === undefined; };
util.isNull = function (val) { return val === null; };
util.isBoolean = function (val) { return typeof val === 'boolean'; };

const path = require('path');
const express = require('express');
const Datastore = require('nedb');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// Отдаём админку (index.html лежит рядом с server.js)
app.use(express.static(__dirname));

// ---- Настройки мода (то, что раньше лежало в mod-key) ----
const MOD_CONFIG = {
    KeyBase64: "xSna3nMZn+i6qPGV4rT0GZ5EgriWF2XGpKBKHeFWPP4=",
    IvBase64: "ZuFERVewWrSKiQxrjr70Jw==",
    ModUrl: "https://github.com/kryytoi/WDdwdw/raw/refs/heads/main/darkvisuals.enc"
};

// База данных
const db = new Datastore({ filename: path.join(__dirname, 'users.db'), autoload: true });
// Уникальный индекс по логину, чтобы не было дублей и удаление всегда попадало точно в цель
db.ensureIndex({ fieldName: 'username', unique: true }, (err) => {
    if (err) console.log('Индекс username:', err.message);
});

// ---- Вспомогательные функции ----

// Промис-обёртки над NeDB, чтобы код был чище и без "callback hell"
const dbFindOne = (query) => new Promise((res, rej) =>
    db.findOne(query, (e, doc) => (e ? rej(e) : res(doc))));

const dbFind = (query) => new Promise((res, rej) =>
    db.find(query, (e, docs) => (e ? rej(e) : res(docs))));

const dbInsert = (doc) => new Promise((res, rej) =>
    db.insert(doc, (e, newDoc) => (e ? rej(e) : res(newDoc))));

const dbUpdate = (query, update, options = {}) => new Promise((res, rej) =>
    db.update(query, update, options, (e, num) => (e ? rej(e) : res(num))));

const dbRemove = (query, options = {}) => new Promise((res, rej) =>
    db.remove(query, options, (e, num) => (e ? rej(e) : res(num))));

const isExpired = (user) => user.expiresAt && new Date() > new Date(user.expiresAt);

// =====================================================================
// 1. АВТОРИЗАЦИЯ ЛАУНЧЕРА (замена Keys.txt)
// =====================================================================
app.post('/api/login', async (req, res) => {
    try {
        const username = (req.body.username || '').trim();
        const password = (req.body.password || '').trim();
        const hwid = (req.body.hwid || '').trim();

        if (!username || !password) {
            return res.json({ success: false, message: "Введите логин и пароль!" });
        }

        const user = await dbFindOne({ username });
        if (!user) return res.json({ success: false, message: "Пользователь не найден" });
        if (user.password !== password) return res.json({ success: false, message: "Неверный пароль" });

        // Бан
        if (user.banned) return res.json({ success: false, message: "Аккаунт заблокирован!" });

        // Истёкшая подписка
        if (isExpired(user)) return res.json({ success: false, message: "Ваша подписка истекла!" });

        // Привязка HWID при первом входе
        if (!user.hwid) {
            await dbUpdate({ _id: user._id }, { $set: { hwid } });
            return res.json({ success: true, message: "HWID привязан", role: user.role || "User" });
        }

        // Проверка HWID
        if (user.hwid !== hwid) {
            return res.json({ success: false, message: "Ошибка: вход с другого ПК (HWID не совпадает)!" });
        }

        return res.json({ success: true, message: "Авторизация успешна", role: user.role || "User" });
    } catch (err) {
        console.log("ОШИБКА /api/login:", err.message);
        return res.json({ success: false, message: "Ошибка сервера: " + err.message });
    }
});

// =====================================================================
// 2. ВЫДАЧА КЛЮЧЕЙ РАСШИФРОВКИ МОДА
// =====================================================================
app.post('/api/mod-key', async (req, res) => {
    try {
        const login = (req.body.login || '').trim();
        const hwid = (req.body.hwid || '').trim();

        const user = await dbFindOne({ username: login });
        if (!user) return res.status(403).json({ error: "Доступ запрещён" });
        if (user.banned) return res.status(403).json({ error: "Аккаунт заблокирован" });
        if (isExpired(user)) return res.status(403).json({ error: "Подписка истекла" });
        if (user.hwid && user.hwid !== hwid) return res.status(403).json({ error: "HWID не совпадает" });

        return res.json(MOD_CONFIG);
    } catch (err) {
        console.log("ОШИБКА /api/mod-key:", err.message);
        return res.status(500).json({ error: "Ошибка сервера" });
    }
});

// =====================================================================
// 3. АДМИН: СПИСОК ВСЕХ
// =====================================================================
app.get('/api/admin/users', async (req, res) => {
    try {
        const users = await dbFind({});
        users.sort((a, b) => (a.username || '').localeCompare(b.username || ''));
        res.json({ success: true, users });
    } catch (err) {
        res.json({ success: false, message: err.message });
    }
});

// =====================================================================
// 4. АДМИН: СОЗДАТЬ ИГРОКА (с таймером подписки)
// =====================================================================
app.post('/api/admin/create', async (req, res) => {
    try {
        const username = (req.body.username || '').trim();
        const password = (req.body.password || '').trim();
        const days = req.body.days;

        if (!username || !password) {
            return res.json({ success: false, message: "Заполните логин и пароль!" });
        }

        const existing = await dbFindOne({ username });
        if (existing) return res.json({ success: false, message: "Такой логин уже существует!" });

        let expiresAt = null;
        if (days && parseInt(days) > 0) {
            const d = new Date();
            d.setDate(d.getDate() + parseInt(days));
            expiresAt = d.toISOString();
        }

        const newDoc = await dbInsert({
            username,
            password,
            hwid: "",
            banned: false,
            role: "User",
            expiresAt,
            createdAt: new Date().toISOString()
        });

        res.json({ success: true, user: newDoc });
    } catch (err) {
        console.log("ОШИБКА /api/admin/create:", err.message);
        res.json({ success: false, message: "Ошибка: " + err.message });
    }
});

// =====================================================================
// 5. АДМИН: БАН / РАЗБАН
// =====================================================================
app.post('/api/admin/toggle-ban', async (req, res) => {
    try {
        const username = (req.body.username || '').trim();
        const banned = !!req.body.banned;

        const num = await dbUpdate({ username }, { $set: { banned } });
        if (num === 0) return res.json({ success: false, message: "Пользователь не найден" });

        res.json({ success: true, banned });
    } catch (err) {
        res.json({ success: false, message: err.message });
    }
});

// =====================================================================
// 6. АДМИН: СБРОС HWID
// =====================================================================
app.post('/api/admin/reset-hwid', async (req, res) => {
    try {
        const username = (req.body.username || '').trim();
        const num = await dbUpdate({ username }, { $set: { hwid: "" } });
        if (num === 0) return res.json({ success: false, message: "Пользователь не найден" });
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, message: err.message });
    }
});

// =====================================================================
// 7. АДМИН: УДАЛИТЬ ПОЛЬЗОВАТЕЛЯ ПОЛНОСТЬЮ
// =====================================================================
app.post('/api/admin/delete', async (req, res) => {
    try {
        const username = (req.body.username || '').trim();
        if (!username) return res.json({ success: false, message: "Не указан логин" });

        const num = await dbRemove({ username }, { multi: true });
        if (num === 0) return res.json({ success: false, message: "Пользователь не найден" });

        // Сжимаем файл базы, чтобы удалённые записи физически исчезли
        db.persistence.compactDatafile();

        res.json({ success: true, removed: num });
    } catch (err) {
        console.log("ОШИБКА /api/admin/delete:", err.message);
        res.json({ success: false, message: err.message });
    }
});

// =====================================================================
// 8. АДМИН: ПРОДЛИТЬ / ИЗМЕНИТЬ ПОДПИСКУ
// =====================================================================
app.post('/api/admin/set-days', async (req, res) => {
    try {
        const username = (req.body.username || '').trim();
        const days = parseInt(req.body.days);

        let expiresAt = null; // 0 / пусто = навсегда
        if (days && days > 0) {
            const d = new Date();
            d.setDate(d.getDate() + days);
            expiresAt = d.toISOString();
        }

        const num = await dbUpdate({ username }, { $set: { expiresAt } });
        if (num === 0) return res.json({ success: false, message: "Пользователь не найден" });
        res.json({ success: true, expiresAt });
    } catch (err) {
        res.json({ success: false, message: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Сервер Dark Visuals запущен на порту ' + PORT));
