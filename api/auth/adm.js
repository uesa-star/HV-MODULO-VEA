/**
 * VEA — Acceso de administración (usuario + contraseña).
 * POST /api/auth/adm { usuario, clave } → crea cookie vea_adm (8 h).
 * DELETE /api/auth/adm → cierra la sesión ADM.
 * Credenciales: VEA_ADM_USER / VEA_ADM_PASS (variables de Vercel).
 */
const crypto = require('crypto');
const { firmar, sesionAdm, cookie, ipDe, userAgentDe, NOMBRE_ADM } = require('./_session');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';

function iguales(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

async function registrarAcceso(fila) {
  const service = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
  if (!service) return;
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/vea_login_log`, {
      method: 'POST',
      headers: {
        apikey: service,
        Authorization: `Bearer ${service}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal'
      },
      body: JSON.stringify(fila),
      cache: 'no-store'
    });
  } catch (_) {
    /* el registro del log nunca bloquea el login */
  }
}

module.exports = async function handler(req, res) {
  if (req.method === 'DELETE') {
    res.setHeader('Set-Cookie', cookie(NOMBRE_ADM, '', 0));
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json({ ok: true });
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST, DELETE');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const usuarioEsperado = process.env.VEA_ADM_USER;
  const claveEsperada = process.env.VEA_ADM_PASS;
  if (!usuarioEsperado || !claveEsperada || !process.env.VEA_AUTH_SECRET) {
    return res.status(503).json({
      error: 'Administración no configurada',
      detalle: 'Faltan VEA_ADM_USER, VEA_ADM_PASS o VEA_AUTH_SECRET en las variables de Vercel.'
    });
  }

  let cuerpo = {};
  try {
    cuerpo = typeof req.body === 'object' && req.body !== null ? req.body : JSON.parse(req.body || '{}');
  } catch (_) {
    return res.status(400).json({ error: 'Cuerpo inválido' });
  }

  const usuario = String(cuerpo.usuario || '');
  const clave = String(cuerpo.clave || '');
  const valido = usuario.length > 0 && clave.length > 0 &&
    iguales(usuario, usuarioEsperado) && iguales(clave, claveEsperada);

  if (!valido) {
    await registrarAcceso({
      email: `adm:${usuario.slice(0, 60) || '(vacío)'}`,
      nombre: 'Intento de acceso ADM',
      proveedor: 'adm',
      ip: ipDe(req),
      user_agent: userAgentDe(req),
      exito: false
    });
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }

  await registrarAcceso({
    email: `adm:${usuarioEsperado}`,
    nombre: 'Administrador',
    proveedor: 'adm',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  const token = firmar({ email: `adm:${usuarioEsperado}`, nombre: 'Administrador', proveedor: 'adm' }, 8);
  res.setHeader('Set-Cookie', cookie(NOMBRE_ADM, token, 8));
  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).json({ ok: true });
};
