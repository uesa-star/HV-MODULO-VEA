/**
 * VEA — Acceso de administración (usuario + contraseña).
 * POST /api/auth/adm
 *   { usuario, clave }              → crea cookie vea_adm (8 h).
 *   { accion:'cambiar', email, claveActual, claveNueva }
 *                                    → cambia la contraseña propia (requiere sesión ADM).
 *   { accion:'restaurar', claveNueva }
 *                                    → la restablece quien tiene sesión Google con el
 *                                      mismo correo registrado («Olvidé mi contraseña»).
 * DELETE /api/auth/adm → cierra la sesión ADM.
 *
 * Credenciales: la contraseña maestra VEA_ADM_PASS (variables de Vercel) siempre
 * funciona; además puede definir SU contraseña en public.vea_config
 * (adm_password_hash + adm_email) y el correo registrado se verifica con Google.
 */
const crypto = require('crypto');
const { firmar, sesion, sesionAdm, cookie, ipDe, userAgentDe, NOMBRE_ADM } = require('../../lib/session');
const { hashearClave, verificarClave } = require('../../lib/clave');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';

function iguales(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function clavesSupabase() {
  const k = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
  return k ? { apikey: k, Authorization: `Bearer ${k}` } : null;
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
    /* el registro del log nunca bloquea el login */
  }
}

function errorTabla(texto) {
  return texto.includes('PGRST205') || texto.includes('42P01');
}

async function leerConfig(req, res) {
  const claves = clavesSupabase();
  if (!claves) return { error: 'Sin credenciales de base de datos en Vercel.' };
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/vea_config?k=in.(adm_password_hash,adm_email)`, {
      headers: claves,
      cache: 'no-store'
    });
    if (r.status === 404) {
      return { error: 'La tabla vea_config no existe. Ejecute el SQL de creación en Supabase.' };
    }
    if (!r.ok) return { error: 'No se pudo leer la configuración. Intente nuevamente.' };
    const filas = await r.json().catch(() => []);
    const cfg = {};
    (Array.isArray(filas) ? filas : []).forEach(function (f) { cfg[String(f.k)] = String(f.v || ''); });
    return { cfg };
  } catch (_) {
    return { error: 'No se pudo contactar con la base de datos. Intente nuevamente.' };
  }
}

async function guardarConfig(pares) {
  const claves = clavesSupabase();
  if (!claves) return false;
  const filas = Object.keys(pares).map(function (k) { return { k: k, v: String(pares[k]) }; });
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/vea_config?on_conflict=k`, {
      method: 'POST',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify(filas),
      cache: 'no-store'
    });
    return r.ok;
  } catch (_) {
    return false;
  }
}

async function cambiarClaveAdm(req, res, cuerpo) {
  if (!sesionAdm(req)) return res.status(401).json({ error: 'Requiere ingreso ADM.' });

  const email = String(cuerpo.email || '').toLowerCase().trim().slice(0, 120);
  const claveActual = String(cuerpo.claveActual || '');
  const claveNueva = String(cuerpo.claveNueva || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return res.status(400).json({ error: 'Correo inválido.' });
  }
  if (claveNueva.length < 8 || claveNueva.length > 72) {
    return res.status(400).json({ error: 'La contraseña nueva debe tener entre 8 y 72 caracteres.' });
  }

  const lectura = await leerConfig(req, res);
  if (lectura.error) return res.status(503).json({ error: lectura.error });
  const cfg = lectura.cfg;

  const esMaestra = Boolean(process.env.VEA_ADM_PASS) && iguales(claveActual, process.env.VEA_ADM_PASS);
  const esPropia = Boolean(cfg.adm_password_hash) && verificarClave(claveActual, cfg.adm_password_hash);
  if (!esMaestra && !esPropia) {
    return res.status(401).json({ error: 'La contraseña actual es incorrecta.' });
  }

  const guardado = await guardarConfig({ adm_password_hash: hashearClave(claveNueva), adm_email: email });
  if (!guardado) {
    return res.status(503).json({ error: 'No se pudo guardar la contraseña. Intente nuevamente.' });
  }

  await registrarAcceso({
    email: `adm:cambió su contraseña (${email})`,
    nombre: 'Administrador',
    proveedor: 'adm',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  return res.status(200).json({ ok: true, email: email });
}

async function restaurarAdmClave(req, res, cuerpo) {
  const s = sesion(req);
  if (!s || s.proveedor !== 'google' || !s.email) {
    return res.status(401).json({
      error: 'Verifíquese con Google primero: ingrese al módulo con su cuenta de Google y vuelva a esta pantalla.'
    });
  }

  const claveNueva = String(cuerpo.claveNueva || '');
  if (claveNueva.length < 8 || claveNueva.length > 72) {
    return res.status(400).json({ error: 'La contraseña nueva debe tener entre 8 y 72 caracteres.' });
  }

  const lectura = await leerConfig(req, res);
  if (lectura.error) return res.status(503).json({ error: lectura.error });
  const cfg = lectura.cfg;

  if (!cfg.adm_email) {
    return res.status(400).json({
      error: 'Aún no registró su correo de administrador. Ingrese con la contraseña maestra y en «Mi contraseña» defina su clave y correo.'
    });
  }
  if (String(s.email).toLowerCase() !== String(cfg.adm_email).toLowerCase()) {
    return res.status(403).json({
      error: `Su correo Google (${s.email}) no coincide con el registrado (${cfg.adm_email}).`
    });
  }

  const guardado = await guardarConfig({ adm_password_hash: hashearClave(claveNueva) });
  if (!guardado) {
    return res.status(503).json({ error: 'No se pudo guardar la contraseña. Intente nuevamente.' });
  }

  await registrarAcceso({
    email: `adm:restableció su contraseña (${String(s.email).toLowerCase()})`,
    nombre: String(s.nombre || 'Administrador'),
    proveedor: 'adm',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  return res.status(200).json({ ok: true });
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

  const accion = String(cuerpo.accion || '');
  if (accion === 'cambiar') return cambiarClaveAdm(req, res, cuerpo);
  if (accion === 'restaurar') return restaurarAdmClave(req, res, cuerpo);

  const usuario = String(cuerpo.usuario || '');
  const clave = String(cuerpo.clave || '');
  let valido = usuario.length > 0 && clave.length > 0 &&
    iguales(usuario, usuarioEsperado) && iguales(clave, claveEsperada);

  if (!valido && usuario.length > 0 && clave.length > 0 && iguales(usuario, usuarioEsperado)) {
    const lectura = await leerConfig(req, res);
    if (!lectura.error && lectura.cfg && lectura.cfg.adm_password_hash) {
      valido = verificarClave(clave, lectura.cfg.adm_password_hash);
    }
  }

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
