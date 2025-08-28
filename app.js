// app.js
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const express        = require('express');
const cookieParser   = require('cookie-parser');
const fetch          = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const bcrypt         = require('bcryptjs');
const jwt            = require('jsonwebtoken');
const sendResetEmail = require('./sendResetEmail.js');

const bookingLocks = new Map();
const app = express();
app.use(express.json({ type: ['application/json', 'application/fhir+json'] }));
app.use(cookieParser());

// ── 常數 ─────────────────────────────────────────────────────────────────────
const JWT_SECRET      = process.env.JWT_SECRET || 'your_fhir_secret_123';
const FHIR_BASE       = 'http://localhost:8080/fhir';
const LOGIN_ID_SYSTEM = 'http://example.org/fhir/login-id';
const EMAIL_SYSTEM    = 'http://example.org/fhir/email';
const PASSWORD_SYSTEM = 'http://example.org/fhir/password';
const IDENTIFIER_SYSTEMS = [LOGIN_ID_SYSTEM, EMAIL_SYSTEM];
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// ── 全域 Debug Middleware ────────────────────────────────────────────────────
app.use((req, res, next) => {
  console.log(`\n[${new Date().toISOString()}] ${req.method} ${req.url}`);
  console.log('  cookies:', req.cookies);
  next();
});

// ── 靜態資源 ─────────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.use('/locales', express.static(path.join(__dirname, 'locales')));
app.get('/', (req, res) => res.redirect('/login.html'));


// ── 1) Person 註冊 /api/register (最佳實踐版本) ────────────────────────────────
app.post('/api/register', async (req, res) => {
  console.log('** [api/register] body:', req.body);
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: '姓名、Email 和密碼皆為必填' });
  }

  try {
    // 檢查 email 是否重複 (此部分不變)
    const chkUrl = `${FHIR_BASE}/Person?identifier=${encodeURIComponent(EMAIL_SYSTEM)}|${encodeURIComponent(email)}`;
    const chkRes = await fetch(chkUrl);
    const chkData = await chkRes.json();
    if (chkData.total > 0) {
      return res.status(409).json({ error: '此 Email 已註冊' });
    }

    // 建立 Person 資源 (此部分不變)
    const person = {
      resourceType: 'Person',
      name: [{ text: name }],
      identifier: [
        { system: EMAIL_SYSTEM,    value: email },
        { system: PASSWORD_SYSTEM, value: await bcrypt.hash(password, 10) }
      ],
      telecom: [{ system: 'email', value: email, use: 'home' }]
    };

    const createUrl = `${FHIR_BASE}/Person`;
    const createRes = await fetch(createUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/fhir+json' },
      body: JSON.stringify(person)
    });
    if (!createRes.ok) {
      throw new Error(await createRes.text());
    }
    const newPerson = await createRes.json();

    // ★ 關鍵修改：產生一個短效、一次性的 "註冊後權杖" (Post-Registration Token)
    const postRegistrationToken = jwt.sign(
      { id: newPerson.id, purpose: 'post-registration' }, // 加入 purpose 聲明用途
      JWT_SECRET,
      { expiresIn: '5m' } // 設定 5 分鐘過期
    );
    console.log('  → 產生註冊後權杖，用於即時登入');

    // ★ 關鍵修改：將權杖回傳給前端
    res.json({
      message: '註冊成功',
      personId: newPerson.id,
      postRegistrationToken: postRegistrationToken
    });

  } catch (err) {
    console.error('  [api/register] error:', err);
    res.status(500).json({ error: '連接 FHIR 錯誤', detail: err.message });
  }
});

// ── 2) Person 登入 /api/login (最佳實踐版本) ────────────────────────────────
app.post('/api/login', async (req, res) => {
  console.log('** [api/login] body:', req.body);
  const { email, password, postRegistrationToken } = req.body; // 接收額外的 Token

  if (!password || (!email && !postRegistrationToken)) {
    return res.status(400).json({ error: '缺少必要參數' });
  }

  try {
    let person = null;

    // ★ 關鍵修改：根據有無 postRegistrationToken 走不同邏輯
    if (postRegistrationToken) {
      // --- 路徑 A：使用註冊後權杖，直接讀取，無延遲 ---
      console.log('  → 使用 post-registration token 進行即時登入');
      try {
        const payload = jwt.verify(postRegistrationToken, JWT_SECRET);
        if (payload.purpose !== 'post-registration') throw new Error('Invalid token purpose');
        
        const personId = payload.id;
        const url = `${FHIR_BASE}/Person/${personId}`; // 直接用 ID 查詢
        console.log('  → direct fetch (no delay)', url);
        const r = await fetch(url);
        if (!r.ok) return res.status(401).json({ error: '無效的註冊後權杖' });
        person = await r.json();
      } catch (err) {
        return res.status(401).json({ error: '註冊後權杖無效或已過期' });
      }
    } else {
      // --- 路徑 B：傳統 Email 登入，透過搜尋 ---
      console.log('  → 使用 email/password 傳統登入');
      const url = `${FHIR_BASE}/Person?identifier=${encodeURIComponent(EMAIL_SYSTEM)}|${encodeURIComponent(email)}`;
      console.log('  → search fetch', url);
      const r = await fetch(url);
      const d = await r.json();
      if (d.total === 0) {
        return res.status(401).json({ error: 'Email 或密碼錯誤' });
      }
      person = d.entry[0].resource;
    }

    // --- 後續密碼比對和簽發正式 Token 的邏輯完全共用 ---
    if (!person) {
      return res.status(401).json({ error: '找不到使用者資料' });
    }

    const hashEntry = person.identifier.find(i => i.system === PASSWORD_SYSTEM);
    if (!hashEntry) {
      return res.status(401).json({ error: '帳號設定有誤' });
    }

    const ok = await bcrypt.compare(password, hashEntry.value);
    if (!ok) {
      return res.status(401).json({ error: 'Email 或密碼錯誤' });
    }

    // 簽發正式的登入 JWT
    const token = jwt.sign({ id: person.id }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true, maxAge: 3600000 });
    res.json({ message: '登入成功' });

  } catch (err) {
    console.error('  [api/login] error:', err);
    res.status(500).json({ error: '登入過程發生錯誤', detail: err.message });
  }
});


// ── 3) 忘記密碼 /api/forgot ───────────────────────────────────────────────────
app.post('/api/forgot', async (req, res) => {
  console.log('** [api/forgot] body:', req.body);
  const { email } = req.body;
  if (!email) {
    console.log('  → email missing 400');
    return res.status(400).json({ error: '請輸入 Email' });
  }
  try {
    const url = `${FHIR_BASE}/Person?identifier=${encodeURIComponent(EMAIL_SYSTEM)}|${encodeURIComponent(email)}`;
    console.log('  → fetch', url);
    const r = await fetch(url);
    console.log('  status', r.status);
    const d = await r.json();
    console.log('  total', d.total);
    if (d.total === 0) {
      console.log('  → 查無此帳號 404');
      return res.status(404).json({ error: '查無此帳號' });
    }

    const pid = d.entry[0].resource.id;
    const tok = jwt.sign({ id: pid }, JWT_SECRET, { expiresIn: '15m' });
    const link = `https://fhirbaser5.duckdns.org/forgot.html?token=${tok}`;
    console.log('  → send reset email link:', link);
    await sendResetEmail(email, link);
    res.json({ message: '已寄出重設密碼連結' });
  } catch (err) {
    console.error('  [api/forgot] error:', err);
    res.status(500).json({ error: '寄信失敗', detail: err.message });
  }
});

// ── 3a：發送重設密碼連結 /api/request-reset ─────────────────────────────────
app.post('/api/request-reset', async (req, res) => {
  console.log('** [api/request-reset] body:', req.body);
  const { email } = req.body;
  if (!email) {
    console.log('  → email missing 400');
    return res.status(400).json({ error: '請輸入 Email' });
  }
  try {
    // 1. 找出對應的 Person
    const url = `${FHIR_BASE}/Person?identifier=${encodeURIComponent(EMAIL_SYSTEM)}|${encodeURIComponent(email)}`;
    console.log('  → fetch', url);
    const r = await fetch(url);
    console.log('  status', r.status);
    const d = await r.json();
    console.log('  total', d.total);
    if (d.total === 0) {
      console.log('  → 查無此帳號 404');
      return res.status(404).json({ error: '查無此帳號' });
    }

    // 2. 產生 Reset Token
    const pid = d.entry[0].resource.id;
    const tok = jwt.sign({ id: pid }, JWT_SECRET, { expiresIn: '15m' });
    const link = `https://fhirbaser5.duckdns.org/reset.html?token=${tok}`;
    console.log('  → reset link:', link);

    // 3. 寄出重設連結
    await sendResetEmail(email, link);
    console.log('  → reset email sent to', email);
    res.json({ message: '已寄出重設密碼連結' });
  } catch (err) {
    console.error('  [api/request-reset] error:', err);
    res.status(500).json({ error: '寄送重設連結失敗', detail: err.message });
  }
});

// ── 4) 重設密碼 /api/reset-password ───────────────────────────────────────────
app.post('/api/reset-password', async (req, res) => {
  console.log('** [api/reset-password] body:', req.body);
  const { token, password } = req.body;
  if (!token||!password) {
    console.log('  → 缺少 token 或 password 400');
    return res.status(400).json({ error: '缺少必要資料' });
  }
  try {
    const { id: pid } = jwt.verify(token, JWT_SECRET);
    console.log('  JWT payload.id =', pid);
    const getUrl = `${FHIR_BASE}/Person/${pid}`;
    console.log('  → fetch', getUrl);
    const getR = await fetch(getUrl);
    console.log('  status', getR.status);
    const person = await getR.json();

    person.identifier = (person.identifier||[])
      .filter(i=>i.system!==PASSWORD_SYSTEM);
    person.identifier.push({
      system: PASSWORD_SYSTEM,
      value: await bcrypt.hash(password, 10)
    });

    const putUrl = `${FHIR_BASE}/Person/${pid}`;
    console.log('  → PUT', putUrl);
    const upd = await fetch(putUrl, {
      method:'PUT',
      headers:{ 'Content-Type':'application/fhir+json' },
      body: JSON.stringify(person)
    });
    console.log('  status', upd.status);
    if (!upd.ok) throw new Error(await upd.text());
    res.json({ message:'密碼已更新' });
  } catch (err) {
    console.error('  [api/reset-password] error:', err);
    res.status(500).json({ error: '重設失敗', detail: err.message });
  }
});