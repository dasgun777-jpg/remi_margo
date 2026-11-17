// api/admin/users.js - Управление доступом сотрудников (ТОЛЬКО для роли margo)
import { getSessionFromReq, invalidateUsersCache } from '../_auth.js';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const session = getSessionFromReq(req);
  if (!session || session.role !== 'margo') {
    return res.status(403).json({ status: 'error', message: 'Доступ запрещён: требуется роль Маргарита' });
  }

  const gasUrl = process.env.GAS_API_URL || 'https://script.google.com/macros/s/AKfycbx2Zrd2LpjMwEEdPwIkr3IvAB83qhJmdbHbkY4kaIC8EecbX872VV0UN1qUZxpqs4zUkA/exec';

  try {
    if (req.method === 'GET') {
      const response = await fetch(`${gasUrl}?action=getSecurityUsers`);
      const data = await response.json();
      return res.status(200).json(data);
    }

    if (req.method === 'POST') {
      const { email, name, role, status } = req.body || {};
      if (!email) {
        return res.status(400).json({ status: 'error', message: 'Email обязателен' });
      }

      const saveUrl = `${gasUrl}?action=saveSecurityUser&email=${encodeURIComponent(email)}&name=${encodeURIComponent(name || '')}&role=${encodeURIComponent(role || 'viewer')}&status=${encodeURIComponent(status || 'Активен')}`;
      const response = await fetch(saveUrl);
      const data = await response.json();

      // Мгновенно сбрасываем кэш, чтобы новый доступ заработал сразу
      invalidateUsersCache();

      return res.status(200).json(data);
    }

    return res.status(405).json({ status: 'error', message: 'Метод не поддерживается' });
  } catch (err) {
    console.error('Admin users error:', err);
    return res.status(500).json({ status: 'error', message: err.toString() });
  }
}
