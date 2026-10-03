/**
 * VEA — Cuentas propias: registro e ingreso con usuario y contraseña.
 * POST /api/auth/cuentas
 *   { accion: 'registro', nombre, usuario, clave, confirm } → crea la cuenta
 *        en public.vea_usuarios (hash scrypt) y devuelve sesión vea_session (12 h).
 *   { accion: 'ingreso', usuario, clave } → valida y devuelve vea_session (12 h).
 */
const { firmar, cookie, ipDe, userAgentDe, NOMBRE_SESION, sesionAdm } = require('../../lib/session');
const { hashearClave, verificarClave, claveFalsa } = require('../../lib/clave');
const { asegurarTablas } = require('../../lib/tablas');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';

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
    /* el log nunca bloquea el ingreso */
  }
}

function errorTabla(texto) {
  return texto.includes('PGRST205') || texto.includes('42P01');
}

async function listarUsuarios(req, res, claves, intento) {
  intento = intento || 0;
  if (!sesionAdm(req)) return res.status(401).json({ error: 'Requiere ingreso ADM.' });

  let r;
  try {
    r = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?select=usuario,nombre,celular,activo,creado_en&order=creado_en.desc&limit=500`, {
      headers: claves,
      cache: 'no-store'
    });
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }

  if (!r.ok) {
    const texto = await r.text().catch(() => '');
    if (r.status === 404 || errorTabla(texto)) {
      if (intento === 0 && await asegurarTablas()) return listarUsuarios(req, res, claves, 1);
      return res.status(503).json({ error: 'La tabla vea_usuarios no existe y no se pudo crear automáticamente. Ejecute el SQL de sql/vea_usuarios.sql en Supabase.' });
    }
    return res.status(500).json({ error: 'No se pudo listar los usuarios. Intente nuevamente.' });
  }

  const filas = await r.json().catch(() => []);
  return res.status(200).json({ usuarios: Array.isArray(filas) ? filas : [] });
}

async function restaurarClave(req, res, cuerpo, claves, intento) {
  intento = intento || 0;
  if (!sesionAdm(req)) return res.status(401).json({ error: 'Requiere ingreso ADM.' });

  const email = String(cuerpo.email || '').toLowerCase().trim().slice(0, 120);
  const clave = String(cuerpo.clave || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return res.status(400).json({ error: 'Correo inválido.' });
  }
  if (clave.length < 8 || clave.length > 72) {
    return res.status(400).json({ error: 'La contraseña debe tener entre 8 y 72 caracteres.' });
  }

  let r;
  try {
    r = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}`, {
      method: 'PATCH',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({ password_hash: hashearClave(clave) }),
      cache: 'no-store'
    });
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }

  if (!r.ok) {
    const texto = await r.text().catch(() => '');
    if (r.status === 404 || errorTabla(texto)) {
      if (intento === 0 && await asegurarTablas()) return restaurarClave(req, res, cuerpo, claves, 1);
      return res.status(503).json({ error: 'La tabla vea_usuarios no existe y no se pudo crear automáticamente. Ejecute el SQL de sql/vea_usuarios.sql en Supabase.' });
    }
    return res.status(500).json({ error: 'No se pudo restablecer la contraseña. Intente nuevamente.' });
  }

  const filas = await r.json().catch(() => []);
  if (!Array.isArray(filas) || !filas.length) {
    return res.status(404).json({ error: 'No existe una cuenta con ese correo.' });
  }

  const adm = sesionAdm(req) || {};
  await registrarAcceso({
    email: `adm:restauró clave → ${email}`,
    nombre: String(adm.email || 'ADM'),
    proveedor: 'adm',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  return res.status(200).json({ ok: true, usuario: email });
}

async function registrar(req, res, cuerpo, claves, intento) {
  intento = intento || 0;
  const nombre = String(cuerpo.nombre || '').trim().slice(0, 80);
  const email = String(cuerpo.email || cuerpo.usuario || '').toLowerCase().trim().slice(0, 120);
  const celular = String(cuerpo.celular || '').replace(/[\s()-]/g, '').slice(0, 20);
  const clave = String(cuerpo.clave || '');
  const confirm = String(cuerpo.confirm || cuerpo.clave || '');

  if (nombre.length < 2) return res.status(400).json({ error: 'Escriba su nombre completo (mínimo 2 letras).' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return res.status(400).json({ error: 'Escriba un correo electrónico válido (ej: juan.perez@hospitaldeventanilla.gob.pe).' });
  }
  if (celular && !/^\+?[0-9]{7,15}$/.test(celular)) {
    return res.status(400).json({ error: 'El celular debe tener solo dígitos (7 a 15 números, puede empezar con +).' });
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
      body: JSON.stringify({ usuario: email, nombre, celular, password_hash: hashearClave(clave) }),
      cache: 'no-store'
    });
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }

  if (!r.ok) {
    const texto = await r.text().catch(() => '');
    if (r.status === 409 || texto.includes('23505')) {
      return res.status(409).json({ error: 'Ese correo ya está registrado. Inicie sesión o use otro correo.' });
    }
    if (r.status === 404 || errorTabla(texto)) {
      if (intento === 0 && await asegurarTablas()) return registrar(req, res, cuerpo, claves, 1);
      return res.status(503).json({ error: 'La tabla vea_usuarios no existe y no se pudo crear automáticamente. Ejecute el SQL de sql/vea_usuarios.sql en Supabase.' });
    }
    if (r.status === 400 && texto.includes('celular')) {
      if (intento === 0 && await asegurarTablas()) return registrar(req, res, cuerpo, claves, 1);
      return res.status(400).json({ error: 'La tabla vea_usuarios no tiene la columna celular. Ejecute el SQL actualizado en Supabase.' });
    }
    return res.status(500).json({ error: 'No se pudo crear la cuenta. Intente nuevamente.' });
  }

  await registrarAcceso({
    email,
    nombre,
    proveedor: 'registro',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  const token = firmar({ email, nombre, proveedor: 'registro' }, 12);
  res.setHeader('Set-Cookie', cookie(NOMBRE_SESION, token, 12));
  return res.status(200).json({ ok: true });
}

async function ingresar(req, res, cuerpo, claves, intento) {
  intento = intento || 0;
  const usuario = String(cuerpo.usuario || cuerpo.email || '').toLowerCase().trim();
  const clave = String(cuerpo.clave || '');
  if (!usuario || !clave) return res.status(400).json({ error: 'Escriba su correo y su contraseña.' });

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
    if (r.status === 404 || errorTabla(texto)) {
      if (intento === 0 && await asegurarTablas()) return ingresar(req, res, cuerpo, claves, 1);
      return res.status(503).json({ error: 'La tabla vea_usuarios no existe y no se pudo crear automáticamente. Ejecute el SQL de sql/vea_usuarios.sql en Supabase.' });
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

  const accion = String(cuerpo.accion || '');
  if (accion === 'registro') return registrar(req, res, cuerpo, claves);
  if (accion === 'ingreso') return ingresar(req, res, cuerpo, claves);
  if (accion === 'usuarios') return listarUsuarios(req, res, claves);
  if (accion === 'restaurar') return restaurarClave(req, res, cuerpo, claves);
  return res.status(400).json({ error: 'Acción inválida (use "registro", "ingreso", "usuarios" o "restaurar").' });
};
