// Password gate for the whole site (HTML, audio, data) using HTTP Basic Auth.
// Credentials come from Vercel Environment Variables, never from the repo:
//   SITE_PASSWORD  (required)  the password
//   SITE_USER      (optional)  the user name, defaults to "aptis"
import { next } from '@vercel/functions';
import { createHash, timingSafeEqual } from 'node:crypto';

const REALM = 'Aptis Luyen De';

// Compare digests so the check takes the same time whatever the input.
const sameSecret = (a, b) => timingSafeEqual(
  createHash('sha256').update(a).digest(),
  createHash('sha256').update(b).digest(),
);

const page = (status, title, body, headers = {}) => new Response(
  `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">`
  + `<title>${title}</title><body style="font:16px system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 16px;color:#16223A">`
  + `<h1 style="font-size:22px">${title}</h1><p>${body}</p></body>`,
  { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...headers } },
);

export default function middleware(request) {
  const password = process.env.SITE_PASSWORD;
  const user = process.env.SITE_USER || 'aptis';

  // Fail closed: without a configured password nobody gets in.
  if (!password) {
    return page(503, 'Trang đang khoá', 'Chưa đặt mật khẩu cho trang. Chủ trang cần thêm biến môi trường SITE_PASSWORD trên Vercel rồi deploy lại.');
  }

  const [scheme, encoded] = (request.headers.get('authorization') || '').split(' ');
  if (scheme === 'Basic' && encoded) {
    const decoded = Buffer.from(encoded, 'base64').toString('utf8');
    const sep = decoded.indexOf(':');
    if (sep >= 0 && sameSecret(decoded.slice(0, sep), user) && sameSecret(decoded.slice(sep + 1), password)) {
      return next();
    }
  }

  return page(401, 'Cần đăng nhập', 'Nhập tên đăng nhập và mật khẩu để vào Aptis Luyện Đề.', {
    'www-authenticate': `Basic realm="${REALM}", charset="UTF-8"`,
  });
}
