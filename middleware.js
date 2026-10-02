/**
 * VEA — Protección de acceso en el borde (Edge Middleware de Vercel).
 * Sin cookie de sesión válida:
 *   - páginas (/ y /index.html) → redirige a /login.html
 *   - APIs (/api/* excepto /api/auth/*) → 401 JSON
 * /login.html, /api/auth/* y los recursos con extensión (imágenes) son públicos.
 */

const PUBLICOS = ['/login.html', '/api/auth/'];

function decodeBase64Url(texto) {
  const normal = texto.replace(/-/g, '+').replace(/_/g, '/');
  const binario = atob(normal);
  const bytes = new Uint8Array(binario.length);
  for (let i = 0; i < binario.length; i++) bytes[i] = binario.charCodeAt(i);
  return bytes;
}

async function verificarSesion(cookieHeader) {
  const secreto = process.env.VEA_AUTH_SECRET;
  if (!secreto || !cookieHeader) return null;

  let token = null;
  for (const par of cookieHeader.split(';')) {
    const [nombre, ...valor] = par.trim().split('=');
    if (nombre === 'vea_session') {
      token = decodeURIComponent(valor.join('='));
      break;
    }
  }
  if (!token) return null;

  const corte = token.lastIndexOf('.');
  if (corte <= 0) return null;
  const payload = token.slice(0, corte);
  const firma = token.slice(corte + 1);

  try {
    const clave = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secreto),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const valido = await crypto.subtle.verify(
      'HMAC',
      clave,
      decodeBase64Url(firma),
      new TextEncoder().encode(payload)
    );
    if (!valido) return null;

    const datos = JSON.parse(new TextDecoder().decode(decodeBase64Url(payload)));
    if (!datos.exp || Date.now() > datos.exp) return null;
    return datos;
  } catch (_) {
    return null;
  }
}

export async function middleware(request) {
  const url = new URL(request.url);
  const ruta = url.pathname;

  if (PUBLICOS.some(p => ruta === p || ruta.startsWith(p))) return;
  if (request.method === 'OPTIONS') return;

  const sesion = await verificarSesion(request.headers.get('cookie'));
  if (sesion) return;

  if (ruta.startsWith('/api/')) {
    return new Response(
      JSON.stringify({ error: 'No autenticado', detalle: 'Ingrese con su cuenta de Google en /login.html' }),
      { status: 401, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } }
    );
  }

  return Response.redirect(new URL('/login.html', url.origin), 307);
}

export const config = {
  matcher: ['/', '/index.html', '/api/:path*']
};
