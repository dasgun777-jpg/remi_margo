// api/data.js - Vercel Serverless Function с контролем сессий и проксированием к Google Apps Script
import { getSessionFromReq } from './_auth.js';

export default async function handler(req, res) {
  // CORS заголовки
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization'
  );

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { action } = req.query;
  if (!action) {
    return res.status(400).json({ status: 'error', message: 'Missing action parameter' });
  }

  // 🔒 1. Проверяем валидность сессии пользователя
  const session = getSessionFromReq(req);

  // Резервная проверка ключа для совместимости
  const cookies = req.headers.cookie || '';
  const cookieMatch = cookies.match(/portal_special_key=([^;]+)/);
  const cookieKey = cookieMatch ? decodeURIComponent(cookieMatch[1].trim()) : '';
  const queryKey = req.query.key || '';
  const isLegacyMargo = queryKey === 'margarita2026' || cookieKey === 'margarita2026';
  const isLegacyShift = queryKey === 'remi131' || cookieKey === 'remi131';

  // Если сессии нет и нет резервного ключа -> Доступ закрыт
  if (!session && !isLegacyMargo && !isLegacyShift) {
    return res.status(401).json({
      status: 'error',
      message: 'Требуется авторизация через Google аккаунт компании'
    });
  }

  const userRole = session ? session.role : (isLegacyMargo ? 'margo' : 'shift');

  // 🔒 2. Разделение прав по ролям:
  // а) Сверка день и Сверка неделя — ТОЛЬКО роль margo
  const SENSITIVE_ACTIONS = ['getDailyReconcileData', 'getReconcileData'];
  if (SENSITIVE_ACTIONS.includes(action)) {
    if (userRole !== 'margo') {
      return res.status(403).json({
        status: 'error',
        message: 'Доступ запрещён: раздел сверок доступен только для роли Маргарита'
      });
    }
  }

  // б) 1 Смена и Карта отработавших — роль margo или shift
  const SHIFT_ACTIONS = ['getShiftData', 'getWorkedMap'];
  if (SHIFT_ACTIONS.includes(action)) {
    if (userRole !== 'margo' && userRole !== 'shift') {
      return res.status(403).json({
        status: 'error',
        message: 'Доступ запрещён: требуется доступ к 1 смене'
      });
    }
  }

  // 3. URL опубликованного скрипта Google Apps Script
  const gasUrl = process.env.GAS_API_URL || 'https://script.google.com/macros/s/AKfycbx2Zrd2LpjMwEEdPwIkr3IvAB83qhJmdbHbkY4kaIC8EecbX872VV0UN1qUZxpqs4zUkA/exec';

  try {
    const targetUrl = `${gasUrl}?action=${encodeURIComponent(action)}`;
    const response = await fetch(targetUrl, {
      method: 'GET',
      redirect: 'follow',
      headers: {
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Google Apps Script responded with HTTP ${response.status}`);
    }

    const data = await response.json();

    // Кэшируем на 60 секунд на edge CDN для быстрой загрузки
    res.setHeader('Cache-Control', 's-maxage=60, stale-while-revalidate=120');
    return res.status(200).json(data);
  } catch (error) {
    console.error('API proxy error:', error);
    return res.status(500).json({ status: 'error', message: error.toString() });
  }
}
