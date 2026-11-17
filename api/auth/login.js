// api/auth/login.js - Проверка токена Google и авторизация по таблице безопасности РЕМИ
import { createSessionToken, getAllowedUsers } from '../_auth.js';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ status: 'error', message: 'Метод не поддерживается' });
  }

  const { credential } = req.body || {};
  if (!credential) {
    return res.status(400).json({ status: 'error', message: 'Отсутствует Google токен (credential)' });
  }

  const gasUrl = process.env.GAS_API_URL || 'https://script.google.com/macros/s/AKfycbx2Zrd2LpjMwEEdPwIkr3IvAB83qhJmdbHbkY4kaIC8EecbX872VV0UN1qUZxpqs4zUkA/exec';
  const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '';
  const userAgent = req.headers['user-agent'] || '';

  try {
    // 1. Проверяем токен напрямую на серверах Google
    const googleRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(credential)}`);
    if (!googleRes.ok) {
      return res.status(401).json({ status: 'error', message: 'Недействительный токен Google' });
    }

    const info = await googleRes.json();
    const expectedClientId = process.env.GOOGLE_CLIENT_ID || '758636874006-c1hhp74b9f02lttco37ojob20ljhmdrd.apps.googleusercontent.com';

    if (info.aud !== expectedClientId) {
      console.warn('Audience mismatch:', info.aud, 'expected:', expectedClientId);
      return res.status(401).json({ status: 'error', message: 'Токен выпущен для другого приложения' });
    }

    if (!info.email || (info.email_verified !== 'true' && info.email_verified !== true)) {
      return res.status(401).json({ status: 'error', message: 'Почта Google не подтверждена' });
    }

    const email = info.email.toLowerCase().trim();
    const allowedMap = await getAllowedUsers();

    // 2. Проверка по таблице безопасности и супер-админам
    let role = allowedMap[email];
    if (!role) {
      // Логируем попытку несанкционированного входа в журнал в фоне
      fetch(`${gasUrl}?action=logSecurityEvent&email=${encodeURIComponent(email)}&name=${encodeURIComponent(info.name || '')}&role=none&device=${encodeURIComponent(userAgent)}&ip=${encodeURIComponent(ip)}&status=Заблокирован+(нет+в+списке)`).catch(() => {});
      
      return res.status(403).json({
        status: 'forbidden',
        message: `Доступ запрещён: адрес ${email} отсутствует в списке авторизованных сотрудников.`
      });
    }

    // 3. Создаём сессию
    const user = {
      email,
      name: info.name || email.split('@')[0],
      picture: info.picture || '',
      role
    };

    const sessionToken = createSessionToken(user);
    res.setHeader(
      'Set-Cookie',
      `remi_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`
    );

    // Логируем успешный вход в Google Таблицу безопасности в фоне
    fetch(`${gasUrl}?action=logSecurityEvent&email=${encodeURIComponent(email)}&name=${encodeURIComponent(user.name)}&role=${encodeURIComponent(role)}&device=${encodeURIComponent(userAgent)}&ip=${encodeURIComponent(ip)}&status=Успешно`).catch(() => {});

    return res.status(200).json({
      status: 'success',
      user
    });

  } catch (err) {
    console.error('Auth error:', err);
    return res.status(500).json({ status: 'error', message: 'Внутренняя ошибка проверки авторизации' });
  }
}
