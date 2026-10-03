/**
 * VEA — Registro de usuario con usuario y contraseña.
 * POST /api/auth/register { nombre, usuario, clave, confirm } → crea la
 * cuenta en public.vea_usuarios (hash scrypt) y devuelve sesión vea_session (12 h).
 */
const crypto = require('crypto');
const { firmar, cookie, ipDe, userAgentDe, NOMBRE_SESION } = require('./_session');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';

function clavesSupabase() {
  const k = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
  return k ? { apikey: k, Authorization: `Bearer ${k}` } : null;
}

function hashearClave(clave) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(clave, salt, 64).toString('hex');
  return `scrypt:${salt}:${hash}`;
}

async function registrarAcceso(fila) {
  const claves = clavesSupabase();
  if (!claves) return;
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/vea_login_log`, {
      method: 'POST',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify(fila),
      cache: 'no-store'
    });
  } catch (_) {
    /* el log nunca bloquea el registro */
  }
}

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  if (!process.env.VEA_AUTH_SECRET) {
    return res.status(503).json({ error: 'Sesión no configurada (falta VEA_AUTH_SECRET en Vercel).' });
  }

  const claves = clavesSupabase();
  if (!claves) {
    return res.status(503).json({ error: 'Base de datos no configurada (faltan credenciales Supabase).' });
  }

  let cuerpo = {};
  try {
    cuerpo = typeof req.body === 'object' && req.body !== null ? req.body : JSON.parse(req.body || '{}');
  } catch (_) {
    return res.status(400).json({ error: 'Cuerpo inválido' });
  }

  const nombre = String(cuerpo.nombre || '').trim().slice(0, 80);
  const usuario = String(cuerpo.usuario || '').toLowerCase().trim();
  const clave = String(cuerpo.clave || '');
  const confirm = String(cuerpo.confirm || cuerpo.clave || '');

  if (nombre.length < 2) return res.status(400).json({ error: 'Escriba su nombre completo (mínimo 2 letras).' });
  if (!/^[a-z0-9._-]{4,30}$/.test(usuario)) {
    return res.status(400).json({ error: 'Usuario inválido: use 4 a 30 caracteres (letras minúsculas, números, punto, guion o guion bajo).' });
  }
  if (clave.length < 8 || clave.length > 72) {
    return res.status(400).json({ error: 'La contraseña debe tener entre 8 y 72 caracteres.' });
  }
  if (clave !== confirm) return res.status(400).json({ error: 'Las contraseñas no coinciden.' });

  let r;
  try {
    r = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios`, {
      method: 'POST',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({ usuario, nombre, password_hash: hashearClave(clave) }),
      cache: 'no-store'
    });
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }

  if (!r.ok) {
    const texto = await r.text().catch(() => '');
    if (r.status === 409 || texto.includes('23505')) {
      return res.status(409).json({ error: 'Ese usuario ya está registrado. Elija otro o inicie sesión.' });
    }
    if (r.status === 404 || texto.includes('PGRST205') || texto.includes('42P01')) {
      return res.status(503).json({ error: 'La tabla vea_usuarios no existe. Ejecute el SQL de creación en Supabase.' });
    }
    return res.status(500).json({ error: 'No se pudo crear la cuenta. Intente nuevamente.' });
  }

  await registrarAcceso({
    email: usuario,
    nombre,
    proveedor: 'registro',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  const token = firmar({ email: usuario, nombre, proveedor: 'registro' }, 12);
  res.setHeader('Set-Cookie', cookie(NOMBRE_SESION, token, 12));
  return res.status(200).json({ ok: true });
};
