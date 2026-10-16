
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

app.disable('x-powered-by');
app.use(express.json({ limit: '32kb' }));

const allowedOrigins = (process.env.FRONTEND_ORIGIN || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (
      !origin ||
      allowedOrigins.length === 0 ||
      allowedOrigins.includes(origin)
    ) {
      return callback(null, true);
    }

    return callback(new Error('Origin not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

const db = new Database(process.env.DB_FILE || 'kitbench.sqlite');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    city TEXT DEFAULT '',
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS pending_registrations (
    email TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    city TEXT DEFAULT '',
    created_at INTEGER NOT NULL
  );
`);

const emailReady = Boolean(
  process.env.SMTP_HOST &&
  process.env.SMTP_USER &&
  process.env.SMTP_PASS &&
  process.env.MAIL_FROM
);

const mailer = emailReady
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 465),
      secure: String(process.env.SMTP_SECURE || 'true') === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      },
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 15000
    })
  : null;

const jwtSecret = process.env.JWT_SECRET;

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 12,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    error: 'Too many attempts. Please wait 15 minutes and try again.'
  }
});

app.use('/api/auth', authLimiter);

function sendError(res, status, message) {
  return res.status(status).json({
    ok: false,
    error: message
  });
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[char]);
}

function codeHash(email, code) {
  return crypto
    .createHash('sha256')
    .update(`${email}:${code}:${process.env.JWT_SECRET}`)
    .digest('hex');
}

function createToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email
    },
    jwtSecret,
    { expiresIn: '7d' }
  );
}

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    emailConfigured: emailReady,
    paymentsConfigured: Boolean(
      process.env.RAZORPAY_KEY_ID &&
      process.env.RAZORPAY_KEY_SECRET
    )
  });
});

// REGISTER: sends an email verification code.
app.post('/api/auth/register', async (req, res) => {
  console.log('[register] request received');

  try {
    const name = typeof req.body.name === 'string'
      ? req.body.name.trim()
      : '';

    const email = typeof req.body.email === 'string'
      ? req.body.email.trim().toLowerCase()
      : '';

    const password = typeof req.body.password === 'string'
      ? req.body.password
      : '';

    const confirmPassword =
      typeof req.body.confirmPassword === 'string'
        ? req.body.confirmPassword
        : '';

    const city = typeof req.body.city === 'string'
      ? req.body.city.trim().slice(0, 80)
      : '';

    if (name.length < 2 || name.length > 80) {
      return sendError(res, 400, 'Enter a name between 2 and 80 characters.');
    }

    if (!validEmail(email)) {
      return sendError(res, 400, 'Enter a valid email address.');
    }

    if (password.length < 8 || password.length > 72) {
      return sendError(res, 400, 'Password must be 8–72 characters long.');
    }

    if (password !== confirmPassword) {
      return sendError(res, 400, 'Passwords do not match.');
    }

    if (!emailReady || !mailer) {
      return sendError(res, 503, 'Email service is not configured.');
    }

    if (!jwtSecret || jwtSecret.length < 32) {
      return sendError(res, 503, 'Server authentication setup is incomplete.');
    }

    const existing = db.prepare(
      'SELECT id, email_verified FROM users WHERE email = ?'
    ).get(email);

    if (existing && existing.email_verified) {
      return sendError(res, 409, 'Account already exists. Please log in.');
    }

    console.log('[register] hashing password');
    const passwordHash = await bcrypt.hash(password, 12);

    const code = String(crypto.randomInt(100000, 1000000));
    const now = Date.now();

    console.log('[register] saving pending registration');

    db.prepare(`
      INSERT INTO pending_registrations
        (email, name, password_hash, code_hash, expires_at,
         attempts, city, created_at)
      VALUES (?, ?, ?, ?, ?, 0, ?, ?)
      ON CONFLICT(email) DO UPDATE SET
        name = excluded.name,
        password_hash = excluded.password_hash,
        code_hash = excluded.code_hash,
        expires_at = excluded.expires_at,
        attempts = 0,
        city = excluded.city,
        created_at = excluded.created_at
    `).run(
      email,
      name,
      passwordHash,
      codeHash(email, code),
      now + 10 * 60 * 1000,
      city,
      now
    );

    console.log('[register] starting email send');

    try {
      await mailer.sendMail({
        from: process.env.MAIL_FROM,
        to: email,
        subject: 'Your KitBench email verification code',
        text:
          `Hello ${name},\n\n` +
          `Your verification code is ${code}. ` +
          'It expires in 10 minutes.',
        html:
          `<p>Hello ${escapeHtml(name)},</p>` +
          '<p>Your KitBench verification code is:</p>' +
          `<p style="font-size:28px;font-weight:bold">${code}</p>` +
          '<p>This code expires in 10 minutes.</p>'
      });

      console.log('[register] email send completed');
    } catch (mailErr) {
      console.error('[register] email failed:', mailErr.message);

      db.prepare(
        'DELETE FROM pending_registrations WHERE email = ?'
      ).run(email);

      return sendError(res, 502, 'Could not send verification email. Check SMTP settings.');
    }

    return res.status(200).json({
      ok: true,
      message: 'Verification code sent. Check your email.'
    });
  } catch (err) {
    console.error('[register] failed:', err.message);
    return sendError(res, 500, 'Could not start registration. Please try again.');
  }
});

// VERIFY EMAIL: frontend must send email and the 6-digit code.
app.post('/api/auth/verify-email', (req, res) => {
  try {
    const email = typeof req.body.email === 'string'
      ? req.body.email.trim().toLowerCase()
      : '';

    const code = typeof req.body.code === 'string'
      ? req.body.code.trim()
      : '';

    if (!validEmail(email) || !/^\d{6}$/.test(code)) {
      return sendError(res, 400, 'Enter a valid email and 6-digit code.');
    }

    const pending = db.prepare(
      'SELECT * FROM pending_registrations WHERE email = ?'
    ).get(email);

    if (!pending) {
      return sendError(res, 400, 'Registration not found. Please sign up again.');
    }

    if (pending.expires_at < Date.now()) {
      db.prepare(
        'DELETE FROM pending_registrations WHERE email = ?'
      ).run(email);

      return sendError(res, 400, 'Code expired. Please sign up again.');
    }

    if (pending.attempts >= 5) {
      db.prepare(
        'DELETE FROM pending_registrations WHERE email = ?'
      ).run(email);

      return sendError(res, 429, 'Too many incorrect attempts. Please sign up again.');
    }

    if (
      !crypto.timingSafeEqual(
        Buffer.from(codeHash(email, code), 'hex'),
        Buffer.from(pending.code_hash, 'hex')
      )
    ) {
      db.prepare(
        'UPDATE pending_registrations SET attempts = attempts + 1 WHERE email = ?'
      ).run(email);

      return sendError(res, 400, 'Incorrect verification code.');
    }

    const result = db.prepare(`
      INSERT INTO users
        (name, email, password_hash, email_verified, city, created_at)
      VALUES (?, ?, ?, 1, ?, ?)
      ON CONFLICT(email) DO UPDATE SET
        name = excluded.name,
        password_hash = excluded.password_hash,
        email_verified = 1,
        city = excluded.city
    `).run(
      pending.name,
      email,
      pending.password_hash,
      pending.city,
      Date.now()
    );

    const user = db.prepare(
      'SELECT id, name, email FROM users WHERE email = ?'
    ).get(email);

    db.prepare(
      'DELETE FROM pending_registrations WHERE email = ?'
    ).run(email);

    return res.json({
      ok: true,
      message: 'Email verified successfully.',
      token: createToken(user),
      user
    });
  } catch (err) {
    console.error('[verify-email] failed:', err.message);
    return sendError(res, 500, 'Could not verify email. Please try again.');
  }
});

// LOGIN: only verified accounts can log in.
app.post('/api/auth/login', async (req, res) => {
  try {
    const email = typeof req.body.email === 'string'
      ? req.body.email.trim().toLowerCase()
      : '';

    const password = typeof req.body.password === 'string'
      ? req.body.password
      : '';

    if (!validEmail(email) || !password) {
      return sendError(res, 400, 'Enter your email and password.');
    }

    const user = db.prepare(`
      SELECT id, name, email, password_hash, email_verified
      FROM users
      WHERE email = ?
    `).get(email);

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return sendError(res, 401, 'Invalid email or password.');
    }

    if (!user.email_verified) {
      return sendError(res, 403, 'Please verify your email first.');
    }

    return res.json({
      ok: true,
      token: createToken(user),
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });
  } catch (err) {
    console.error('[login] failed:', err.message);
    return sendError(res, 500, 'Login failed. Please try again.');
  }
});

app.use((err, _req, res, _next) => {
  console.error('[server] request error:', err.message);

  if (res.headersSent) return;

  res.status(500).json({
    ok: false,
    error: 'Server request failed.'
  });
});

app.listen(PORT, () => {
  console.log(`KitBench API listening on port ${PORT}`);
});
