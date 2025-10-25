// api/send.js
// Vercel Serverless Function (Node). Place at /api/send.js
// Environment variables required: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
// Optional: API_SECRET (simple header-based secret), RECAPTCHA_SECRET (server-side verification).

import fetch from 'node-fetch';

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID   = process.env.TELEGRAM_CHAT_ID;
const API_SECRET         = process.env.API_SECRET || '';
const RECAPTCHA_SECRET   = process.env.RECAPTCHA_SECRET || '';

// Basic safety checks on startup
if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
  console.error('Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID in environment.');
}

// Basic in-memory rate limiting per IP (limited but helps reduce casual abuse).
// Note: serverless instances may be short-lived / replicated; for robust limits use Redis.
const RATE_WINDOW_MS = 60_000; // 1 minute
const MAX_PER_WINDOW = 6;
const ipMap = new Map();

function tooManyRequests(ip) {
  const now = Date.now();
  const arr = ipMap.get(ip) || [];
  // remove stale
  const kept = arr.filter(t => t > now - RATE_WINDOW_MS);
  kept.push(now);
  ipMap.set(ip, kept);
  return kept.length > MAX_PER_WINDOW;
}

function escapeHtml(s) {
  return s.replaceAll('&', '&amp;')
          .replaceAll('<', '&lt;')
          .replaceAll('>', '&gt;')
          .replaceAll('"', '&quot;')
          .replaceAll("'", '&#39;');
}

// Optional: very small profanity list (example). Expand or replace with a proper filter if needed.
const simpleProfanity = ['fuck','shit','bitch','asshole','nigger','cunt'];
function containsProfanity(s) {
  const low = s.toLowerCase();
  return simpleProfanity.some(w => low.includes(w));
}

// Serverless handler for Vercel
export default async function handler(req, res) {
  // Only POST
  if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'Method not allowed' });

  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';

  if (tooManyRequests(ip)) {
    return res.status(429).json({ ok: false, error: 'Too many requests. Try again later.' });
  }

  // Optional API secret header check (set API_SECRET in env to enable)
  if (API_SECRET) {
    const header = req.headers['x-api-secret'] || '';
    if (!header || header !== API_SECRET) {
      return res.status(401).json({ ok: false, error: 'Unauthorized' });
    }
  }

  const { message } = req.body || {};
  if (!message || typeof message !== 'string') return res.status(400).json({ ok: false, error: 'Invalid message' });

  const trimmed = message.trim().slice(0, 1000);
  if (trimmed.length === 0) return res.status(400).json({ ok: false, error: 'Empty message' });

  // Optional: reCAPTCHA server-side verification (if you want extra bot protection)
  // Expect client to send recaptchaToken in body, then verify here using RECAPTCHA_SECRET.
  // If you want this, add code to verify with Google's endpoint.

  // Moderation filter example: profanity check
  if (containsProfanity(trimmed)) {
    return res.status(400).json({ ok: false, error: 'Message contains prohibited language' });
  }

  // Sanitize/escape to avoid markup injection in Telegram (we'll send as plain text)
  const safe = escapeHtml(trimmed);

  const text = `📨 Anonymous message:\n${safe}`;

  // Send to Telegram API
  try {
    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
    const params = new URLSearchParams({
      chat_id: TELEGRAM_CHAT_ID,
      text,
      parse_mode: 'HTML'
    });

    const tgRes = await fetch(url, { method: 'POST', body: params });
    const tgJson = await tgRes.json();

    if (!tgJson || !tgJson.ok) {
      console.error('Telegram API error', tgJson);
      return res.status(502).json({ ok: false, error: 'Failed to deliver to Telegram' });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error('Send error', err);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
}
