// api/admin/logs.js - Журнал безопасности и сессий (ТОЛЬКО для роли margo)
import { getSessionFromReq } from '../_auth.js';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const session = getSessionFromReq(req);
  if (!session || session.role !== 'margo') {
    return res.status(403).json({ status: 'error', message: 'Доступ запрещён: требуется роль Маргарита' });
  }

  const gasUrl = process.env.GAS_API_URL || 'https://script.google.com/macros/s/AKfycbx2Zrd2LpjMwEEdPwIkr3IvAB83qhJmdbHbkY4kaIC8EecbX872VV0UN1qUZxpqs4zUkA/exec';

  try {
    const response = await fetch(`${gasUrl}?action=getSecurityLogs`);
    const data = await response.json();
    return res.status(200).json(data);
  } catch (err) {
    console.error('Admin logs error:', err);
    return res.status(500).json({ status: 'error', message: err.toString() });
  }
}
