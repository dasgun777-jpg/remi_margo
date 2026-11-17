// api/portal.js - Защищённый серверный шлюз портала РЕМИ (Server-Side Role-Based HTML Gateway)
import fs from 'fs';
import path from 'path';
import { getSessionFromReq } from './_auth.js';

export default async function handler(req, res) {
  // 1. Проверяем наличие криптографически подписанной сессии
  const session = getSessionFromReq(req);

  // Резервная проверка ключа для совместимости
  const cookies = (req.headers && req.headers.cookie) || '';
  const cookieMatch = cookies.match(/portal_special_key=([^;]+)/);
  const cookieKey = cookieMatch ? decodeURIComponent(cookieMatch[1].trim()) : '';
  const queryKey = (req.query && req.query.key) || '';
  const isLegacyMargo = queryKey === 'margarita2026' || cookieKey === 'margarita2026';
  const isLegacyShift = queryKey === 'remi131' || cookieKey === 'remi131';

  if (!session && !isLegacyMargo && !isLegacyShift) {
    // Неавторизованный пользователь -> мгновенный серверный редирект на экран входа /
    res.writeHead(302, { Location: '/' });
    return res.end();
  }

  const user = session || {
    email: isLegacyMargo ? 'margo@remi.local' : 'shift@remi.local',
    name: isLegacyMargo ? 'Маргарита' : '1 Смена',
    picture: '',
    role: isLegacyMargo ? 'margo' : 'shift'
  };

  const userRole = user.role || 'viewer';

  try {
    // 2. Считываем изолированный шаблон портала
    const templatePath = path.join(process.cwd(), 'portal.html');
    let html = fs.readFileSync(templatePath, 'utf8');

    // 🔒 3. СЕРВЕРНАЯ ИЗОЛЯЦИЯ СВЕРОК:
    // Если пользователь НЕ Маргарита, физически вырезаем разметку Сверок из HTML
    if (userRole !== 'margo') {
      html = html.replace(/<!-- SPECIAL_START -->[\s\S]*?<!-- SPECIAL_END -->/g, '');
    }

    // 🔒 4. СЕРВЕРНАЯ ИЗОЛЯЦИЯ 1 СМЕНЫ:
    // Если пользователь НЕ Маргарита и НЕ 1 Смена (роль viewer), вырезаем 1 Смену
    if (userRole !== 'margo' && userRole !== 'shift') {
      html = html.replace(/<!-- SHIFT_NAV_START -->[\s\S]*?<!-- SHIFT_NAV_END -->/g, '');
      html = html.replace(/<!-- SHIFT_PANE_START -->[\s\S]*?<!-- SHIFT_PANE_END -->/g, '');
    }

    // 5. Внедряем безопасные данные сессии в DOM
    const safeUserJson = JSON.stringify({
      email: user.email,
      name: user.name,
      picture: user.picture,
      role: userRole
    });

    html = html.replace(
      '<!-- USER_INJECTION_POINT -->',
      `<script>window.__CURRENT_USER__ = ${safeUserJson};</script>`
    );

    // Запрет кэширования персонального HTML в браузерах и CDN
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    return res.status(200).send(html);

  } catch (err) {
    console.error('Error rendering portal template:', err);
    return res.status(500).send('Внутренняя ошибка загрузки портала');
  }
}
