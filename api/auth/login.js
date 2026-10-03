/**
 * VEA — Ingreso con usuario y contraseña (cuentas de public.vea_usuarios).
 * POST /api/auth/login { usuario, clave } → crea cookie vea_session (12 h).
 */
const crypto = require('crypto');
const { firmar, cookie, ipDe, userAgentDe, NOMBRE_SESION } = require('./_session');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';

function clavesSupabase() {
  const k = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
  return k ? { apikey: k, Authorization: `Bearer ${k}` } : null;
}

function verificarClave(clave, almacenado) {
  try {
    const partes = String(almacenado || '').split(':');
    if (partes.length !== 3 || partes[0] !== 'scrypt') return false;
    const salt = partes[1];
    const hash = Buffer.from(partes[2], 'hex');
    const candidato = crypto.scryptSync(clave, salt, 64);
    if (candidato.length !== hash.length) return false;
    return crypto.timingSafeEqual(candidato, hash);
  } catch (_) {
    return false;
  }
}

function claveFalsa() {
  try { crypto.scryptSync('x', 'sal_falsa_00000000', 64); } catch (_) { /* noop */ }
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
    /* el log nunca bloquea el login */
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

  const usuario = String(cuerpo.usuario || '').toLowerCase().trim();
  const clave = String(cuerpo.clave || '');
  if (!usuario || !clave) {
    return res.status(400).json({ error: 'Escriba su usuario y su contraseña.' });
  }

  let r;
  try {
    r = await fetch(
      `${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(usuario)}&select=nombre,password_hash,activo&limit=1`,
      { headers: claves, cache: 'no-store' }
    );
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }

  if (!r.ok) {
    const texto = await r.text().catch(() => '');
    if (r.status === 404 || texto.includes('PGRST205') || texto.includes('42P01')) {
      return res.status(503).json({ error: 'La tabla vea_usuarios no existe. Ejecute el SQL de creación en Supabase.' });
    }
    return res.status(500).json({ error: 'No se pudo verificar la cuenta. Intente nuevamente.' });
  }

  const filas = await r.json().catch(() => []);
  const fila = Array.isArray(filas) && filas.length ? filas[0] : null;
  const correcta = fila ? verificarClave(clave, fila.password_hash) : (claveFalsa(), false);
  const activo = fila && fila.activo !== false;

  if (!fila || !correcta || !activo) {
    await registrarAcceso({
      email: `registro:${usuario.slice(0, 60) || '(vacío)'}`,
      nombre: 'Intento de acceso con usuario/contraseña',
      proveedor: 'registro',
      ip: ipDe(req),
      user_agent: userAgentDe(req),
      exito: false
    });
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }

  await registrarAcceso({
    email: usuario,
    nombre: fila.nombre || usuario,
    proveedor: 'registro',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  const token = firmar({ email: usuario, nombre: fila.nombre || usuario, proveedor: 'registro' }, 12);
  res.setHeader('Set-Cookie', cookie(NOMBRE_SESION, token, 12));
  return res.status(200).json({ ok: true });
};
