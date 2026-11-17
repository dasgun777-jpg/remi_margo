// api/auth/me.js - Проверка текущей сессии пользователя
import { getSessionFromReq } from '../_auth.js';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const session = getSessionFromReq(req);
  if (!session) {
    return res.status(200).json({ authenticated: false });
  }

  return res.status(200).json({
    authenticated: true,
    user: {
      email: session.email,
      name: session.name,
      picture: session.picture,
      role: session.role
    }
  });
}
