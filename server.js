/* ============================================================
 * Nova — Backend proxy for Alight premium API
 * Node.js + Express — Optimized for Vercel
 * ============================================================ */
import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cookieSession from 'cookie-session';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';

const app = express();
const PORT = process.env.PORT || 3000;

/* ---------- Config (SECRETS live only in env) ---------- */
const ALIGHT_BASE = process.env.ALIGHT_BASE_URL || 'https://alightfree.my.id';
const ALIGHT_API_KEY = process.env.ALIGHT_API_KEY;

if (!ALIGHT_API_KEY) {
  console.error('[FATAL] ALIGHT_API_KEY is not set.');
  // Di Vercel, jangan process.exit — biarkan route yang error saja
  // process.exit(1);
}

/* ---------- Security middleware ---------- */
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

/* ---------- Session cookie ---------- */
app.use(cookieSession({
  name: 'nova.sid',
  keys: [process.env.SESSION_SECRET || 'change-me-in-production'],
  maxAge: 30 * 60 * 1000, // 30 menit
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
}));

/* ---------- CSRF: same-origin check ---------- */
app.use((req, res, next) => {
  if (req.method === 'POST') {
    const origin = req.get('origin');
    const host = req.get('host');
    if (origin) {
      try {
        const originHost = new URL(origin).host;
        if (originHost !== host) {
          return res.status(403).json({ message: 'Forbidden' });
        }
      } catch {
        return res.status(403).json({ message: 'Forbidden' });
      }
    }
  }
  next();
});

/* ---------- Rate limiting ---------- */
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Terlalu banyak permintaan. Mohon pelan-pelan.' },
});

const strictLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { message: 'Terlalu banyak percobaan. Tunggu sebentar.' },
});

app.use('/api/', apiLimiter);

/* ---------- Validation schemas ---------- */
const EmailSchema = z.string().trim().toLowerCase().email().max(254);
const LinkSchema = z.string().trim().url().max(2048);

/* ---------- Helpers ---------- */
async function callAlight(path, body) {
  if (!ALIGHT_API_KEY) {
    const err = new Error('Server belum dikonfigurasi (API key missing)');
    err.status = 500;
    throw err;
  }

  const res = await fetch(`${ALIGHT_BASE}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ALIGHT_API_KEY,
    },
    body: JSON.stringify(body),
  });

  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch { /* noop */ }

  if (!res.ok) {
    const err = new Error(
      (data && (data.message || data.error)) || `Upstream error (${res.status})`
    );
    err.status = res.status;
    throw err;
  }
  return data;
}

function safeError(res, err) {
  const status = err.status && err.status < 500 ? err.status : 502;
  const messages = {
    400: 'Permintaan tidak valid. Periksa kembali dan coba lagi.',
    401: 'Autentikasi gagal. Silakan minta tautan baru.',
    403: 'Aksi ini tidak diizinkan.',
    404: 'Sumber daya tidak ditemukan.',
    409: 'Permintaan bertentangan dengan status saat ini.',
    429: 'Terlalu banyak permintaan. Coba lagi nanti.',
    500: 'Server belum dikonfigurasi dengan benar.',
  };
  const message = messages[status] || 'Layanan sementara tidak tersedia. Coba lagi.';
  res.status(status).json({ message });
}

/* ============================================================
 * ROUTES
 * ============================================================ */

/* Health check — berguna untuk monitoring Vercel */
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    hasApiKey: !!ALIGHT_API_KEY,
    env: process.env.NODE_ENV || 'development',
    ts: Date.now(),
  });
});

/* Send magic link */
app.post('/api/send-magiclink', strictLimiter, async (req, res) => {
  const parsed = EmailSchema.safeParse(req.body?.email);
  if (!parsed.success) {
    return res.status(400).json({ message: 'Masukkan alamat email yang valid.' });
  }
  try {
    await callAlight('/api/v1/send-magiclink', { email: parsed.data });
    req.session.email = parsed.data;
    res.json({ ok: true, sent: true, message: 'Magic link terkirim.' });
  } catch (err) {
    safeError(res, err);
  }
});

/* Verify account */
app.post('/api/verify-account', strictLimiter, async (req, res) => {
  const email = EmailSchema.safeParse(req.body?.email);
  const link = LinkSchema.safeParse(req.body?.rawLink);

  if (!email.success || !link.success) {
    return res.status(400).json({ message: 'Email atau tautan verifikasi tidak valid.' });
  }

  try {
    const data = await callAlight('/api/v1/verify-account', {
      email: email.data,
      rawLink: link.data,
    });

    const idToken = data?.idToken || data?.data?.idToken || data?.token;
    if (!idToken) {
      return res.status(502).json({ message: 'Verifikasi tidak mengembalikan token yang valid.' });
    }

    req.session.email = email.data;
    req.session.idToken = idToken;
    req.session.verifiedAt = Date.now();

    res.json({ ok: true, verified: true });
  } catch (err) {
    safeError(res, err);
  }
});

/* Apply premium */
app.post('/api/apply-premium', strictLimiter, async (req, res) => {
  const email = EmailSchema.safeParse(req.body?.email);
  if (!email.success) {
    return res.status(400).json({ message: 'Email tidak valid.' });
  }

  const idToken = req.session?.idToken;
  if (!idToken || req.session.email !== email.data) {
    return res.status(401).json({ message: 'Sesi berakhir. Silakan verifikasi lagi.' });
  }

  try {
    await callAlight('/api/v1/apply-premium', {
      email: email.data,
      idToken,
    });

    req.session.idToken = null;

    res.json({ ok: true, success: true });
  } catch (err) {
    safeError(res, err);
  }
});

/* ============================================================
 * STATIC FILES
 * ============================================================
 * Di Vercel, express.static() di-ignore. Vercel otomatis serve
 * folder /public dari CDN. Blok ini tetap dipertahankan untuk
 * development lokal (node server.js).
 * ============================================================ */
  const { default: path } = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const __dirname = path.dirname(fileURLToPath(import.meta.url));

  app.use(express.static(path.resolve(__dirname, 'public'), {
    maxAge: '1h',
    setHeaders(res, filePath) {
      if (filePath.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-cache');
      }
    },
  }));

  app.get('*', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'public/index.html'));
  });
}

/* ============================================================
 * LISTEN
 * ============================================================
 * Di Vercel, app.listen() dideteksi otomatis dan di-handle.
 * Di lokal, ini start server biasa.
 * ============================================================ */
if (process.env.VERCEL !== '1') {
  app.listen(PORT, () => {
    console.log(`Nova listening on :${PORT}`);
  });
}

/* Export untuk Vercel serverless */
export default app;
