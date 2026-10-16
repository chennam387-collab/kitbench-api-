require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const Razorpay = require('razorpay');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));
const allowedOrigins = (process.env.FRONTEND_ORIGIN || '').split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({ origin(origin, callback) { if (!origin || !allowedOrigins.length || allowedOrigins.includes(origin)) return callback(null, true); return callback(new Error('Origin not allowed by CORS')); }, methods: ['GET','POST','PATCH','OPTIONS'] }));

const db = new Database(process.env.DB_FILE || 'kitbench.sqlite');
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email_verified INTEGER NOT NULL DEFAULT 0, city TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS pending_registrations (email TEXT PRIMARY KEY, name TEXT NOT NULL, password_hash TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, city TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS project_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, category TEXT NOT NULL, level TEXT NOT NULL, hardware TEXT NOT NULL DEFAULT '', details TEXT NOT NULL DEFAULT '', email TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'New', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);`);
// Safe migrations for databases created by earlier versions.
for (const [table, column, definition] of [['users','city',"TEXT NOT NULL DEFAULT ''"],['pending_registrations','city',"TEXT NOT NULL DEFAULT ''"]]) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
  if (!columns.includes(column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many attempts. Please wait 15 minutes and try again.' } });
app.use('/api/auth', authLimiter);
// Email: Render's free plan blocks SMTP ports, so Brevo's web API (HTTPS) is used when BREVO_API_KEY is set.
// SMTP settings still work as a fallback on hosts that allow them.
const brevoReady = Boolean(process.env.BREVO_API_KEY && process.env.MAIL_FROM);
const smtpReady = Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS && process.env.MAIL_FROM);
const emailReady = brevoReady || smtpReady;
function parseSender(from) { const m = String(from).match(/^\s*(?:"?([^"<]*?)"?\s*)?<([^>]+)>\s*$/); return m ? { name: (m[1] || 'KitBench').trim() || 'KitBench', email: m[2].trim() } : { name: 'KitBench', email: String(from).trim() }; }
const smtpMailer = smtpReady ? nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: String(process.env.SMTP_SECURE || 'false') === 'true', auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } }) : null;
const mailer = !emailReady ? null : {
  async sendMail(opts) {
    if (!brevoReady) return smtpMailer.sendMail(opts);
    const res = await fetch('https://api.brevo.com/v3/smtp/email', { method: 'POST', headers: { 'api-key': process.env.BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ sender: parseSender(opts.from), to: [{ email: opts.to }], subject: opts.subject, htmlContent: opts.html, textContent: opts.text }) });
    if (!res.ok) throw new Error('Brevo API ' + res.status + ': ' + (await res.text()).slice(0, 200));
  }
};
const jwtSecret = process.env.JWT_SECRET;
function validEmail(email) { return typeof email === 'string' && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function codeHash(email, code) { return crypto.createHmac('sha256', process.env.OTP_SECRET || process.env.JWT_SECRET || 'configure-a-long-random-secret').update(email.toLowerCase() + ':' + code).digest('hex'); }
function sendError(res, status, error) { return res.status(status).json({ error }); }
app.get('/health', (_req, res) => res.json({ ok: true, emailConfigured: emailReady, emailVerificationRequired: String(process.env.REQUIRE_EMAIL_VERIFICATION || 'true').toLowerCase() !== 'false', emailMethod: brevoReady ? 'brevo-api' : (smtpReady ? 'smtp' : 'none'), paymentsConfigured: Boolean(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET) }));

// Aggregate verified student counts. City counts are shown only when at least 3 accounts share a city.
// Project requests are stored centrally in SQLite, not in an individual student's browser.
const requestLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many project requests. Please try again later.' } });
app.post('/api/project-requests', requestLimiter, (req, res) => {
  try {
    const title = typeof req.body.title === 'string' ? req.body.title.trim() : '';
    const category = typeof req.body.category === 'string' ? req.body.category.trim().slice(0, 60) : '';
    const level = typeof req.body.level === 'string' ? req.body.level.trim().slice(0, 40) : '';
    const hardware = typeof req.body.hardware === 'string' ? req.body.hardware.trim().slice(0, 160) : '';
    const details = typeof req.body.details === 'string' ? req.body.details.trim().slice(0, 700) : '';
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    if (title.length < 3 || title.length > 120) return sendError(res, 400, 'Project idea must be between 3 and 120 characters.');
    if (!category || !level) return sendError(res, 400, 'Choose a project area and level.');
    if (email && !validEmail(email)) return sendError(res, 400, 'Enter a valid email address or leave it blank.');
    const result = db.prepare("INSERT INTO project_requests(title,category,level,hardware,details,email,status) VALUES(?,?,?,?,?,?,'New')").run(title, category, level, hardware, details, email);
    const request = db.prepare('SELECT id,title,category,level,hardware,details,email,status,created_at,updated_at FROM project_requests WHERE id = ?').get(result.lastInsertRowid);
    res.status(201).json({ ok: true, request, message: 'Your request was sent to KitBench successfully.' });
  } catch (err) { console.error('Project request save failed:', err.message); sendError(res, 500, 'Could not save your project request. Please try again.'); }
});
function requireAdmin(req, res, next) {
  const expected = process.env.ADMIN_API_TOKEN || '';
  const supplied = req.get('x-admin-token') || '';
  if (expected.length < 32) return sendError(res, 503, 'Admin access is not configured. The site owner must set ADMIN_API_TOKEN on the backend.');
  const a = Buffer.from(supplied), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return sendError(res, 401, 'Admin token is incorrect.');
  next();
}
app.get('/api/admin/project-requests', requireAdmin, (_req, res) => {
  try { const requests = db.prepare('SELECT id,title,category,level,hardware,details,email,status,created_at,updated_at FROM project_requests ORDER BY created_at DESC, id DESC LIMIT 500').all(); res.json({ ok: true, requests }); }
  catch (err) { console.error('Admin request list failed:', err.message); sendError(res, 500, 'Could not load project requests.'); }
});
app.patch('/api/admin/project-requests/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id), status = typeof req.body.status === 'string' ? req.body.status : '';
  const allowed = ['New', 'Under Review', 'Approved', 'In Development', 'Completed', 'Declined'];
  if (!Number.isSafeInteger(id) || id < 1 || !allowed.includes(status)) return sendError(res, 400, 'Invalid request ID or status.');
  try { const result = db.prepare('UPDATE project_requests SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(status, id); if (!result.changes) return sendError(res, 404, 'Project request not found.'); res.json({ ok: true, id, status }); }
  catch (err) { console.error('Admin request update failed:', err.message); sendError(res, 500, 'Could not update request status.'); }
});

app.get('/api/community/stats', (_req, res) => {
  try {
    const totalVerified = db.prepare('SELECT COUNT(*) AS count FROM users WHERE email_verified = 1').get().count;
    const cities = db.prepare(`SELECT city, COUNT(*) AS count FROM users WHERE email_verified = 1 AND TRIM(city) <> '' GROUP BY LOWER(TRIM(city)) HAVING COUNT(*) >= 3 ORDER BY count DESC, city COLLATE NOCASE ASC LIMIT 12`).all();
    res.set('Cache-Control', 'public, max-age=60');
    res.json({ totalVerified, cities: cities.map(row => ({ city: row.city, count: row.count })) });
  } catch (err) { console.error('Community stats failed:', err.message); sendError(res, 500, 'Community statistics are unavailable.'); }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    const city = typeof req.body.city === 'string' ? req.body.city.trim().slice(0, 80) : '';
    const confirmPassword = typeof req.body.confirmPassword === 'string' ? req.body.confirmPassword : '';
    if (name.length < 2 || name.length > 80) return sendError(res, 400, 'Enter a name between 2 and 80 characters.');
    if (!validEmail(email)) return sendError(res, 400, 'Enter a valid email address.');
    if (password.length < 8 || password.length > 72) return sendError(res, 400, 'Password must be 8–72 characters long.');
    if (password !== confirmPassword) return sendError(res, 400, 'Passwords do not match.');
    const skipVerify = String(process.env.REQUIRE_EMAIL_VERIFICATION || 'true').toLowerCase() === 'false';
    if (skipVerify) {
      // Simple mode: no email code. Anyone can create an account with any email address.
      if (!jwtSecret || jwtSecret.length < 32) return sendError(res, 503, 'Account server setup is incomplete. The site owner must configure JWT_SECRET.');
      const dup = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
      if (dup) return sendError(res, 409, 'An account already exists for this email. Please log in.');
      db.prepare('INSERT INTO users(name,email,password_hash,email_verified,city) VALUES(?,?,?,1,?)').run(name, email, await bcrypt.hash(password, 12), city);
      return res.status(200).json({ ok: true, verified: true, message: 'Account created. You can now log in.' });
    }
    if (!emailReady) return sendError(res, 503, 'Email verification is not configured yet. The site owner must configure SMTP settings on the backend.');
    if (!jwtSecret || jwtSecret.length < 32) return sendError(res, 503, 'Account server setup is incomplete. The site owner must configure JWT_SECRET.');
    const existing = db.prepare('SELECT id, email_verified FROM users WHERE email = ?').get(email);
    if (existing && existing.email_verified) return sendError(res, 409, 'An account already exists for this email. Please log in.');
    const code = String(crypto.randomInt(100000, 1000000));
    const passwordHash = await bcrypt.hash(password, 12);
    const now = Date.now();
    db.prepare(`INSERT INTO pending_registrations(email,name,password_hash,code_hash,expires_at,attempts,city,created_at) VALUES(?,?,?,?,?,0,?,?) ON CONFLICT(email) DO UPDATE SET name=excluded.name,password_hash=excluded.password_hash,code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0,city=excluded.city,created_at=excluded.created_at`).run(email, name, passwordHash, codeHash(email, code), now + 10 * 60 * 1000, city, now);
    try {
      await mailer.sendMail({ from: process.env.MAIL_FROM, to: email, subject: 'Your KitBench email verification code', text: `Hello ${name},\n\nYour KitBench verification code is ${code}. It expires in 10 minutes.\n\nIf you did not request this, you can ignore this email.`, html: `<p>Hello ${escapeHtml(name)},</p><p>Your KitBench verification code is:</p><p style="font-size:28px;font-weight:bold;letter-spacing:6px">${code}</p><p>This code expires in 10 minutes. If you did not request it, ignore this email.</p>` });
    } catch (mailErr) {
      db.prepare('DELETE FROM pending_registrations WHERE email = ?').run(email);
      console.error('Verification email failed:', mailErr.message);
      return sendError(res, 502, 'Could not send the verification email. Check the email address or try again later.');
    }
    return res.status(200).json({ ok: true, message: 'Verification code sent. Check your email.' });
  } catch (err) { console.error('Registration failed:', err.message); return sendError(res, 500, 'Could not start registration. Please try again.'); }
});
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

app.post('/api/auth/verify-email', (req, res) => {
  try {
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const code = typeof req.body.code === 'string' ? req.body.code.trim() : '';
    if (!validEmail(email) || !/^\d{6}$/.test(code)) return sendError(res, 400, 'Enter the email address and 6-digit code.');
    const pending = db.prepare('SELECT * FROM pending_registrations WHERE email = ?').get(email);
    if (!pending) return sendError(res, 400, 'No pending registration was found. Register again to get a new code.');
    if (Date.now() > pending.expires_at) { db.prepare('DELETE FROM pending_registrations WHERE email = ?').run(email); return sendError(res, 400, 'Code expired. Please register again to receive a new code.'); }
    if (pending.attempts >= 5) { db.prepare('DELETE FROM pending_registrations WHERE email = ?').run(email); return sendError(res, 429, 'Too many incorrect codes. Please register again.'); }
    if (!crypto.timingSafeEqual(Buffer.from(codeHash(email, code), 'hex'), Buffer.from(pending.code_hash, 'hex'))) {
      db.prepare('UPDATE pending_registrations SET attempts = attempts + 1 WHERE email = ?').run(email);
      return sendError(res, 400, 'Incorrect verification code. Please check your email and try again.');
    }
    db.prepare('INSERT INTO users(name,email,password_hash,email_verified,city) VALUES(?,?,?,1,?) ON CONFLICT(email) DO UPDATE SET name=excluded.name,password_hash=excluded.password_hash,email_verified=1,city=excluded.city').run(pending.name, email, pending.password_hash, pending.city || '');
    db.prepare('DELETE FROM pending_registrations WHERE email = ?').run(email);
    return res.json({ ok: true, verified: true, message: 'Email verified. You can now log in.' });
  } catch (err) { console.error('Email verification failed:', err.message); return sendError(res, 500, 'Could not verify the email. Please try again.'); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';
    if (!validEmail(email) || !password) return sendError(res, 400, 'Enter your email and password.');
    if (!jwtSecret || jwtSecret.length < 32) return sendError(res, 503, 'Account server setup is incomplete. The site owner must configure JWT_SECRET.');
    const user = db.prepare('SELECT id,name,email,password_hash,email_verified FROM users WHERE email = ?').get(email);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return sendError(res, 401, 'Email or password is incorrect.');
    if (!user.email_verified) return sendError(res, 403, 'Verify your email before logging in.');
    const token = jwt.sign({ sub: String(user.id), email: user.email }, jwtSecret, { expiresIn: '2h', issuer: 'kitbench' });
    return res.json({ ok: true, token, user: { name: user.name, email: user.email, emailVerified: true } });
  } catch (err) { console.error('Login failed:', err.message); return sendError(res, 500, 'Could not log in. Please try again.'); }
});

// Razorpay is optional while setting up accounts. Configure both keys to enable payments.
const paymentsConfigured = Boolean(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET);
const razorpay = paymentsConfigured ? new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET }) : null;
// Prices (in paise) are read from catalog.json so customers cannot change them in the browser.
const PRODUCT_CATALOG = require('./catalog.json');
app.post('/api/create-order', async (req, res) => {
  if (!razorpay) return sendError(res, 503, 'Razorpay is not configured on the server.');
  try {
    const items = req.body.items;
    if (!Array.isArray(items) || items.length < 1 || items.length > 30) return sendError(res, 400, 'Invalid cart.');
    let amount = 0; const receiptItems = [];
    for (const item of items) { const product = PRODUCT_CATALOG[item.id]; const quantity = Number(item.quantity); if (!product || !Number.isInteger(quantity) || quantity < 1 || quantity > 20) return sendError(res, 400, `Invalid or unavailable kit: ${item.id}`); amount += product.price * quantity; receiptItems.push({ id: item.id, quantity, title: product.title }); }
    if (!amount || amount > 50000000) return sendError(res, 400, 'Order amount is invalid.');
    const order = await razorpay.orders.create({ amount, currency: 'INR', receipt: `kb_${Date.now()}`, notes: { item_summary: JSON.stringify(receiptItems).slice(0, 450) } });
    res.json({ id: order.id, amount: order.amount, currency: order.currency });
  } catch (err) { console.error('Create order failed:', err.message); return sendError(res, 500, 'Unable to create payment order.'); }
});
app.post('/api/verify-payment', async (req, res) => {
  if (!razorpay) return res.status(503).json({ verified: false, error: 'Razorpay is not configured on the server.' });
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    if (![razorpay_order_id, razorpay_payment_id, razorpay_signature].every(v => typeof v === 'string' && v.length)) return res.status(400).json({ verified: false, error: 'Missing payment details.' });
    const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(`${razorpay_order_id}|${razorpay_payment_id}`).digest('hex');
    const a = Buffer.from(expected, 'hex'), b = Buffer.from(razorpay_signature, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(400).json({ verified: false, error: 'Signature verification failed.' });
    const payment = await razorpay.payments.fetch(razorpay_payment_id);
    if (payment.order_id !== razorpay_order_id || payment.status !== 'captured') return res.status(400).json({ verified: false, error: 'Payment is not captured for this order.' });
    res.json({ verified: true, paymentId: payment.id });
  } catch (err) { console.error('Verify payment failed:', err.message); return res.status(500).json({ verified: false, error: 'Unable to verify payment.' }); }
});
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`KitBench API listening on port ${port}`));
