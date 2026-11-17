// api/_auth.js - Модуль безопасной сессионной аутентификации (HMAC SHA-256 + Cookies)
import crypto from 'crypto';

const SECRET = process.env.SESSION_SECRET || 'remi-default-session-secret-change-in-vercel-env-2026';

export function createSessionToken(user) {
  const payload = {
    email: user.email,
    name: user.name || '',
    picture: user.picture || '',
    role: user.role || 'viewer',
    exp: Date.now() + 7 * 24 * 60 * 60 * 1000 // Срок жизни 7 дней
  };
  const payloadStr = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(payloadStr).digest('base64url');
  return `${payloadStr}.${sig}`;
}

export function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadStr, sig] = parts;
  
  const expectedSig = crypto.createHmac('sha256', SECRET).update(payloadStr).digest('base64url');
  if (sig !== expectedSig) return null;
  
  try {
    const payload = JSON.parse(Buffer.from(payloadStr, 'base64url').toString('utf8'));
    if (!payload || !payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

export function parseCookies(req) {
  const list = {};
  const rc = req.headers?.cookie;
  if (rc) {
    rc.split(';').forEach(cookie => {
      const parts = cookie.split('=');
      const key = parts.shift().trim();
      list[key] = decodeURIComponent(parts.join('='));
    });
  }
  return list;
}

export function getSessionFromReq(req) {
  const cookies = parseCookies(req);
  return verifySessionToken(cookies.remi_session);
}

export function parseAllowedEmails() {
  const raw = process.env.ALLOWED_EMAILS || '';
  const map = {};
  if (!raw.trim()) return map;

  if (raw.trim().startsWith('{')) {
    try {
      const obj = JSON.parse(raw);
      for (const [k, v] of Object.entries(obj)) {
        map[k.toLowerCase().trim()] = (v || 'viewer').toLowerCase().trim();
      }
      return map;
    } catch (e) {
      console.error('Ошибка парсинга JSON в ALLOWED_EMAILS:', e);
    }
  }

  const items = raw.split(/[\n,;]+/);
  for (const item of items) {
    const trimmed = item.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(':');
    const email = parts[0].toLowerCase().trim();
    const role = (parts[1] || 'viewer').toLowerCase().trim();
    if (email) {
      map[email] = role;
    }
  }
  return map;
}

// Кэш пользователей из Google Таблицы безопасности (срок жизни 2 минуты)
let cachedUsersMap = null;
let lastCacheTime = 0;

export async function getAllowedUsers() {
  const now = Date.now();
  if (cachedUsersMap && (now - lastCacheTime < 120000)) {
    return cachedUsersMap;
  }

  const map = { ...parseAllowedEmails() };
  
  // Встроенные супер-администраторы с максимальным доступом margo
  map['dimaipakov74@gmail.com'] = 'margo';
  map['margarita198947@gmail.com'] = 'margo';
  map['dasgun777@gmail.com'] = 'margo';
  map['roacalanagaren@gmail.com'] = 'margo';

  const gasUrl = process.env.GAS_API_URL || 'https://script.google.com/macros/s/AKfycbx2Zrd2LpjMwEEdPwIkr3IvAB83qhJmdbHbkY4kaIC8EecbX872VV0UN1qUZxpqs4zUkA/exec';

  try {
    const res = await fetch(`${gasUrl}?action=getSecurityUsers`, { redirect: 'follow' });
    if (res.ok) {
      const json = await res.json();
      if (json && json.status === 'success' && Array.isArray(json.data)) {
        for (const u of json.data) {
          if (u.email && u.status === 'Активен') {
            map[u.email.toLowerCase().trim()] = (u.role || 'viewer').toLowerCase().trim();
          } else if (u.email && u.status === 'Заблокирован') {
            delete map[u.email.toLowerCase().trim()];
          }
        }
      }
    }
  } catch (err) {
    console.warn('Could not fetch security users from Google Sheet, using cache/env:', err);
  }

  cachedUsersMap = map;
  lastCacheTime = now;
  return map;
}

export function invalidateUsersCache() {
  cachedUsersMap = null;
  lastCacheTime = 0;
}
