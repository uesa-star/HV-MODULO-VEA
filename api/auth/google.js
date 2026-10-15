/**
 * VEA — Autenticación con Google.
 * GET /api/auth/google                 → redirige a la pantalla de Google.
 * GET /api/auth/config                 → { google, adm, secret } (rewrite a
 *   ?recurso=config). Se fusionó aquí para no superar el límite de 12
 *   Serverless Functions del plan Hobby de Vercel.
 * Requiere GOOGLE_CLIENT_ID y GOOGLE_CLIENT_SECRET en Vercel.
 */
const crypto = require('crypto');
const { cookie } = require('../../lib/session');

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  // Config de acceso (antes api/auth/config.js).
  if (String(req.query.recurso || '') === 'config') {
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    return res.status(200).json({
      google: Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
      adm: Boolean(process.env.VEA_ADM_USER && process.env.VEA_ADM_PASS),
      secret: Boolean(process.env.VEA_AUTH_SECRET)
    });
  }

  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret || !process.env.VEA_AUTH_SECRET) {
    res.setHeader('Cache-Control', 'no-store');
    return res.status(503).json({
      error: 'Login con Google no configurado',
      detalle: 'Faltan GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET o VEA_AUTH_SECRET en las variables de Vercel.'
    });
  }

  const host = process.env.VEA_BASE_URL || 'vigilancia-epidemiologica-ecru.vercel.app';
  const redirectUri = `https://${host}/api/auth/callback`;
  const state = crypto.randomBytes(24).toString('base64url');

  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid email profile');
  url.searchParams.set('state', state);
  url.searchParams.set('prompt', 'select_account');
  url.searchParams.set('access_type', 'online');

  res.setHeader('Set-Cookie', cookie('vea_oauth_state', state, 0.2));
  res.setHeader('Cache-Control', 'no-store');
  // El botón del login navega directo: se redirige a Google (no se devuelve JSON).
  if (String(req.query.format || '') === 'json') {
    return res.status(200).json({ url: url.toString(), redirect_uri: redirectUri });
  }
  res.setHeader('Location', url.toString());
  return res.status(302).end();
};
