// api/data.js - Vercel Serverless Function с контролем доступа и проксированием к Google Apps Script
export default async function handler(req, res) {
  // CORS заголовки
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  const { action } = req.query;
  if (!action) {
    return res.status(400).json({ status: 'error', message: 'Missing action parameter' });
  }

  // 🔒 Проверка доступа к конфиденциальным действиям (Сверка день и Сверка неделя)
  const SENSITIVE_ACTIONS = ['getDailyReconcileData', 'getReconcileData'];
  if (SENSITIVE_ACTIONS.includes(action)) {
    const cookies = req.headers.cookie || '';
    const cookieMatch = cookies.match(/portal_special_key=([^;]+)/);
    const cookieKey = cookieMatch ? decodeURIComponent(cookieMatch[1].trim()) : '';
    const queryKey = req.query.key || '';

    if (queryKey !== 'margarita2026' && cookieKey !== 'margarita2026') {
      return res.status(403).json({
        status: 'error',
        message: 'Доступ запрещен: требуется ключ авторизации Маргариты'
      });
    }
  }

  // URL опубликованного скрипта Google Apps Script
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

    // Кэшируем на 60 секунд на edge CDN для молниеносной скорости загрузки
    res.setHeader('Cache-Control', 's-maxage=60, stale-while-revalidate=120');
    return res.status(200).json(data);
  } catch (error) {
    console.error('API proxy error:', error);
    return res.status(500).json({ status: 'error', message: error.toString() });
  }
}
