/* ============================================================
 * Nova — Backend proxy for Alight premium API
 * Sessions stored in Supabase (Vercel-safe)
 * ============================================================ */
import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

const ALIGHT_BASE = process.env.ALIGHT_BASE_URL || 'https://alightfree.my.id';
const ALIGHT_API_KEY = process.env.ALIGHT_API_KEY;

const SUPABASE_URL = 'https://sdjgbrkjhguoiwouwcti.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNkamdicmtqaGd1b2l3b3V3Y3RpIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTE1MjExNTAsImV4cCI6MjEwNzA5NzE1MH0.Sm40JEXnvbAzbA-dN-V_eCyoJz_G9_DyTAie1te55-E';

if (!ALIGHT_API_KEY) console.error('[WARN] ALIGHT_API_KEY is not set.');

app.disable('x-powered-by');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://unpkg.com', 'https://cdn.jsdelivr.net'],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: [
        "'self'",
        'https://raw.githubusercontent.com',
        'https://api.github.com',
        'https://sdjgbrkjhguoiwouwcti.supabase.co',
        'wss://sdjgbrkjhguoiwouwcti.supabase.co',
      ],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

app.use(express.json({ limit: '10kb' }));

/* ---------- Supabase helper ---------- */
async function sbQuery(pathname, options = {}) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${pathname}`, {
    ...options,
    headers: {
      'apikey': SUPABASE_ANON_KEY,
      'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=representation',
      ...(options.headers || {}),
    },
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { /* noop */ }
  if (!res.ok) throw new Error((data && data.message) || `Supabase ${res.status}`);
  return data;
}

function randomId() {
  return 'sess_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
}

/* ---------- CSRF ---------- */
app.use((req, res, next) => {
  if (req.method === 'POST') {
    const origin = req.get('origin');
    const host = req.get('host');
    if (origin) {
      try {
        if (new URL(origin).host !== host) return res.status(403).json({ message: 'Forbidden' });
      } catch {
        return res.status(403).json({ message: 'Forbidden' });
      }
    }
  }
  next();
});

/* ---------- Rate limit ---------- */
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false, message: { message: 'Terlalu banyak permintaan.' } });
const strictLimiter = rateLimit({ windowMs: 60 * 1000, max: 10, message: { message: 'Terlalu banyak percobaan.' } });
app.use('/api/', apiLimiter);

/* ---------- Schemas ---------- */
const EmailSchema = z.string().trim().toLowerCase().email().max(254);
const LinkSchema = z.string().trim().url().max(2048);
const SessionIdSchema = z.string().trim().min(4).max(64);

/* ---------- Alight proxy ---------- */
async function callAlight(pathname, body) {
  if (!ALIGHT_API_KEY) {
    const err = new Error('Server belum dikonfigurasi');
    err.status = 500;
    throw err;
  }
  const res = await fetch(`${ALIGHT_BASE}${pathname}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': ALIGHT_API_KEY },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch { /* noop */ }
  if (!res.ok) {
    const err = new Error((data && (data.message || data.error)) || `Upstream ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

function safeError(res, err) {
  const status = err.status && err.status < 500 ? err.status : 502;
  const messages = {
    400: 'Permintaan tidak valid.',
    401: 'Autentikasi gagal.',
    403: 'Aksi tidak diizinkan.',
    404: 'Sumber daya tidak ditemukan.',
    429: 'Terlalu banyak permintaan.',
    500: 'Server belum dikonfigurasi.',
  };
  res.status(status).json({ message: messages[status] || 'Layanan sementara tidak tersedia.' });
}

/* ---------- ROUTES ---------- */

app.get('/api/health', (req, res) => {
  res.json({ ok: true, hasApiKey: !!ALIGHT_API_KEY, env: process.env.NODE_ENV || 'development', ts: Date.now() });
});

app.post('/api/send-magiclink', strictLimiter, async (req, res) => {
  const parsed = EmailSchema.safeParse(req.body?.email);
  if (!parsed.success) return res.status(400).json({ message: 'Email tidak valid.' });
  try {
    await callAlight('/api/v1/send-magiclink', { email: parsed.data });
    res.json({ ok: true, sent: true });
  } catch (err) { safeError(res, err); }
});

app.post('/api/verify-account', strictLimiter, async (req, res) => {
  const email = EmailSchema.safeParse(req.body?.email);
  const link = LinkSchema.safeParse(req.body?.rawLink);
  if (!email.success || !link.success) return res.status(400).json({ message: 'Input tidak valid.' });

  try {
    const data = await callAlight('/api/v1/verify-account', { email: email.data, rawLink: link.data });
    const idToken = data?.idToken || data?.data?.idToken || data?.token;
    if (!idToken) return res.status(502).json({ message: 'Token tidak valid dari server.' });

    const sessionId = randomId();
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();

    await sbQuery('sessions', {
      method: 'POST',
      body: JSON.stringify({
        id: sessionId,
        email: email.data,
        id_token: idToken,
        expires_at: expiresAt,
      }),
    });

    res.json({ ok: true, verified: true, sessionId });
  } catch (err) { safeError(res, err); }
});

app.post('/api/apply-premium', strictLimiter, async (req, res) => {
  const email = EmailSchema.safeParse(req.body?.email);
  const sessionId = SessionIdSchema.safeParse(req.body?.sessionId);
  if (!email.success || !sessionId.success) return res.status(400).json({ message: 'Data tidak valid.' });

  try {
    const rows = await sbQuery(`sessions?id=eq.${encodeURIComponent(sessionId.data)}&select=*`);
    const sess = rows && rows[0];
    if (!sess) return res.status(401).json({ message: 'Sesi berakhir. Silakan verifikasi lagi.' });
    if (sess.email !== email.data) return res.status(401).json({ message: 'Sesi tidak cocok.' });
    if (new Date(sess.expires_at) < new Date()) return res.status(401).json({ message: 'Sesi kedaluwarsa.' });

    await callAlight('/api/v1/apply-premium', { email: email.data, idToken: sess.id_token });

    await sbQuery(`sessions?id=eq.${encodeURIComponent(sessionId.data)}`, { method: 'DELETE' });

    res.json({ ok: true, success: true });
  } catch (err) { safeError(res, err); }
});

/* ---------- Static + Listen ---------- */
app.use(express.static(path.resolve(__dirname, 'public')));
app.get('*', (req, res) => {
  res.sendFile(path.resolve(__dirname, 'public/index.html'));
});

if (!process.env.VERCEL) {
  app.listen(PORT, () => console.log(`Nova listening on :${PORT}`));
}

export default app;
