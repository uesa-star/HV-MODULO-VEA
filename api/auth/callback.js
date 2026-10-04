/**
 * VEA — Callback OAuth de Google.
 * GET /api/auth/callback?code=...&state=...
 * Intercambia el código, verifica la identidad (userinfo), registra el
 * acceso en vea_login_log y crea la cookie de sesión firmada.
 */
const { firmar, leerCookie, cookie, ipDe, userAgentDe, nuevoSid } = require('../../lib/session');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';

function redirigir(res, destino) {
  res.setHeader('Location', destino);
  res.setHeader('Cache-Control', 'no-store');
  return res.status(302).end();
}

function clavesSupabase() {
  const service = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (service) return { apikey: service, authorization: `Bearer ${service}` };
  const anon = process.env.SUPABASE_ANON_KEY;
  return anon ? { apikey: anon, authorization: `Bearer ${anon}` } : null;
}

async function registrarAcceso(fila) {
  const claves = clavesSupabase();
  if (!claves) return false;
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/vea_login_log`, {
      method: 'POST',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify(fila),
      cache: 'no-store'
    });
    return r.ok;
  } catch (_) {
    return false;
  }
}

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const code = String(req.query.code || '');
  const state = String(req.query.state || '');
  const estadoEsperado = leerCookie(req, 'vea_oauth_state');
  const error = String(req.query.error || '');

  if (error) {
    return redirigir(res, `/login.html?e=${encodeURIComponent(error)}`);
  }
  if (!code || !state || !estadoEsperado || state !== estadoEsperado) {
    return redirigir(res, '/login.html?e=state');
  }

  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret || !process.env.VEA_AUTH_SECRET) {
    return redirigir(res, '/login.html?e=config');
  }

  try {
    const host = req.headers.host || 'vigilancia-epidemiologica-ecru.vercel.app';
    const intercambio = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: `https://${host}/api/auth/callback`,
        grant_type: 'authorization_code'
      }),
      cache: 'no-store'
    });
    if (!intercambio.ok) {
      return redirigir(res, '/login.html?e=token');
    }
    const tokens = await intercambio.json();

    const userinfo = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
      cache: 'no-store'
    });
    if (!userinfo.ok) {
      return redirigir(res, '/login.html?e=userinfo');
    }
    const perfil = await userinfo.json();

    if (!perfil.email || perfil.email_verified !== true) {
      return redirigir(res, '/login.html?e=verificado');
    }

    const sid = nuevoSid();
    await registrarAcceso({
      email: String(perfil.email).toLowerCase(),
      nombre: String(perfil.name || '').slice(0, 200),
      proveedor: 'google',
      ip: ipDe(req),
      user_agent: userAgentDe(req),
      exito: true,
      sesion_id: sid
    });

    const sesion = firmar(
      {
        sub: String(perfil.sub || ''),
        email: String(perfil.email).toLowerCase(),
        nombre: String(perfil.name || perfil.email).slice(0, 200),
        foto: String(perfil.picture || '').slice(0, 400),
        proveedor: 'google',
        sid: sid
      },
      12
    );

    res.setHeader('Set-Cookie', [
      cookie('vea_session', sesion, 12),
      cookie('vea_oauth_state', '', 0)
    ]);
    return redirigir(res, '/');
  } catch (err) {
    console.error('[VEA AUTH callback]', err);
    return redirigir(res, '/login.html?e=interno');
  }
};
