/**
 * VEA — Cuentas propias: registro e ingreso con usuario y contraseña.
 * POST /api/auth/cuentas
 *   { accion: 'registro', nombre, usuario, clave, confirm } → crea la cuenta
 *        en public.vea_usuarios (hash scrypt) y devuelve sesión vea_session (12 h).
 *   { accion: 'ingreso', usuario, clave } → valida y devuelve vea_session (12 h).
 *        Si la cuenta tiene debe_cambiar (clave temporal puesta por el ADM),
 *        responde { debe_cambiar: true } y el cliente obliga a cambiarla.
 *   { accion: 'cambiarPropia', claveActual, claveNueva } → el usuario con
 *        sesión propia cambia su contraseña y quita la marca debe_cambiar.
 *   { accion: 'enviarCodigoUsuario', email } → envía código de 6 dígitos al
 *        correo del usuario (recuperación "olvidé mi contraseña"; máx. 3/15 min).
 *   { accion: 'restaurarConCodigoUsuario', email, codigo, claveNueva }
 *        → restablece con el código recibido (vence 10 min, máx. 5 intentos).
 */
const crypto = require('crypto');
const { firmar, cookie, sesion, ipDe, userAgentDe, nuevoSid, NOMBRE_SESION } = require('../../lib/session');
const { hashearClave, verificarClave, claveFalsa } = require('../../lib/clave');
const { enviarCorreo } = require('../../lib/correo');
const { asegurarTablas } = require('../../lib/tablas');
const { admActivo, FALLOS_USUARIO, MINUTOS_BLOQUEO } = require('../../lib/control');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';
const COD_EXPIRA_MS = 10 * 60 * 1000;   // el código de recuperación vence a los 10 min
const COD_INTENTOS = 5;                 // intentos fallidos antes de destruir el código
const COD_REENVIO_MS = 60 * 1000;       // 1 envío como mínimo por minuto
const COD_ENVIOS_MAX = 3;               // máx. 3 envíos por correo cada 15 min

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
  if (!(await admActivo(req))) return res.status(401).json({ error: 'Requiere ingreso ADM.' });

  let r;
  try {
    r = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?select=usuario,nombre,celular,activo,debe_cambiar,creado_en&order=creado_en.desc&limit=500`, {
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
  const adm = await admActivo(req);
  if (!adm) return res.status(401).json({ error: 'Requiere ingreso ADM.' });

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
      body: JSON.stringify({ password_hash: hashearClave(clave), debe_cambiar: true }),
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

  const admDatos = adm || {};
  await registrarAcceso({
    email: `adm:restauró clave → ${email}`,
    nombre: String(admDatos.email || 'ADM'),
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

  const sidReg = nuevoSid();
  await registrarAcceso({
    email,
    nombre,
    proveedor: 'registro',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true,
    sesion_id: sidReg
  });

  const token = firmar({ email, nombre, proveedor: 'registro', sid: sidReg }, 12);
  res.setHeader('Set-Cookie', cookie(NOMBRE_SESION, token, 12));
  return res.status(200).json({ ok: true });
}

async function ingresar(req, res, cuerpo, claves, intento) {
  intento = intento || 0;
  const usuario = String(cuerpo.usuario || cuerpo.email || '').toLowerCase().trim();
  const clave = String(cuerpo.clave || '');
  if (!usuario || !clave) return res.status(400).json({ error: 'Escriba su correo y su contraseña.' });

  // Anti fuerza bruta: bloquea tras 10 intentos fallidos en 15 minutos.
  try {
    const corte = new Date(Date.now() - MINUTOS_BLOQUEO * 60000).toISOString();
    const rf = await fetch(
      `${SUPABASE_URL}/rest/v1/vea_login_log?email=eq.${encodeURIComponent('registro:' + usuario)}` +
      `&exito=eq.false&creado_en=gte.${encodeURIComponent(corte)}&select=id`,
      { headers: claves, cache: 'no-store' }
    );
    if (rf.ok) {
      const fallos = await rf.json().catch(() => []);
      if (Array.isArray(fallos) && fallos.length >= FALLOS_USUARIO) {
        return res.status(429).json({
          error: `Demasiados intentos fallidos para esta cuenta. Intente de nuevo en ${MINUTOS_BLOQUEO} minutos.`
        });
      }
    }
  } catch (_) { /* sin conteo: continuar */ }

  let r;
  try {
    r = await fetch(
      `${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(usuario)}&select=nombre,password_hash,activo,debe_cambiar&limit=1`,
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

  const sidIng = nuevoSid();
  await registrarAcceso({
    email: usuario,
    nombre: fila.nombre || usuario,
    proveedor: 'registro',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true,
    sesion_id: sidIng
  });

  const debeCambiar = fila.debe_cambiar === true;
  const datosToken = { email: usuario, nombre: fila.nombre || usuario, proveedor: 'registro', sid: sidIng };
  if (debeCambiar) datosToken.dc = 1;
  const token = firmar(datosToken, 12);
  res.setHeader('Set-Cookie', cookie(NOMBRE_SESION, token, 12));
  return res.status(200).json({ ok: true, debe_cambiar: debeCambiar });
}

async function cambiarClavePropia(req, res, cuerpo, claves, intento) {
  intento = intento || 0;
  const datos = sesion(req);
  if (!datos || datos.proveedor !== 'registro' || !datos.email) {
    return res.status(401).json({ error: 'Requiere ingreso con correo y contraseña.' });
  }
  const usuario = String(datos.email).toLowerCase().trim().slice(0, 120);
  const actual = String(cuerpo.claveActual || '');
  const nueva = String(cuerpo.claveNueva || cuerpo.clave || '');
  if (nueva.length < 8 || nueva.length > 72) {
    return res.status(400).json({ error: 'La contraseña debe tener entre 8 y 72 caracteres.' });
  }

  let r;
  try {
    r = await fetch(
      `${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(usuario)}&select=password_hash&limit=1`,
      { headers: claves, cache: 'no-store' }
    );
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }

  if (!r.ok) {
    const texto = await r.text().catch(() => '');
    if (r.status === 404 || errorTabla(texto)) {
      if (intento === 0 && await asegurarTablas()) return cambiarClavePropia(req, res, cuerpo, claves, 1);
      return res.status(503).json({ error: 'La tabla vea_usuarios no existe y no se pudo crear automáticamente. Ejecute el SQL de sql/vea_usuarios.sql en Supabase.' });
    }
    return res.status(500).json({ error: 'No se pudo verificar la cuenta. Intente nuevamente.' });
  }

  const filas = await r.json().catch(() => []);
  const fila = Array.isArray(filas) && filas.length ? filas[0] : null;
  if (!fila) return res.status(404).json({ error: 'No existe una cuenta con ese correo.' });
  if (!verificarClave(actual, fila.password_hash)) {
    return res.status(401).json({ error: 'La contraseña actual es incorrecta.' });
  }

  let r2;
  try {
    r2 = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(usuario)}`, {
      method: 'PATCH',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ password_hash: hashearClave(nueva), debe_cambiar: false }),
      cache: 'no-store'
    });
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }
  if (!r2.ok) return res.status(500).json({ error: 'No se pudo guardar la nueva contraseña. Intente nuevamente.' });

  await registrarAcceso({
    email: usuario,
    nombre: String(datos.nombre || usuario),
    proveedor: 'registro',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  const token = firmar({ email: usuario, nombre: datos.nombre || usuario, proveedor: 'registro', sid: datos.sid }, 12);
  res.setHeader('Set-Cookie', cookie(NOMBRE_SESION, token, 12));
  return res.status(200).json({ ok: true });
}

const MSJ_GENERICO = 'Si existe una cuenta con ese correo, le enviamos un código de 6 dígitos (vence en 10 minutos). Revise su bandeja de entrada.';

async function enviarCodigoUsuario(req, res, cuerpo, claves, intento) {
  intento = intento || 0;
  const email = String(cuerpo.email || '').toLowerCase().trim().slice(0, 120);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return res.status(400).json({ error: 'Correo inválido.' });
  }
  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
    return res.status(503).json({ error: 'El servicio de correo aún no está configurado en el servidor.' });
  }

  // Máximo 3 envíos por correo cada 15 minutos (cuenta existente o no).
  try {
    const corte = new Date(Date.now() - MINUTOS_BLOQUEO * 60000).toISOString();
    const rf = await fetch(
      `${SUPABASE_URL}/rest/v1/vea_login_log?email=eq.${encodeURIComponent('cod:' + email)}` +
      `&creado_en=gte.${encodeURIComponent(corte)}&select=id`,
      { headers: claves, cache: 'no-store' }
    );
    if (rf.ok) {
      const envios = await rf.json().catch(() => []);
      if (Array.isArray(envios) && envios.length >= COD_ENVIOS_MAX) {
        return res.status(429).json({ error: `Demasiadas solicitudes para este correo. Espere ${MINUTOS_BLOQUEO} minutos.` });
      }
    }
  } catch (_) { /* sin conteo: continuar */ }

  let r;
  try {
    r = await fetch(
      `${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}&select=activo,cod_enviado&limit=1`,
      { headers: claves, cache: 'no-store' }
    );
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }

  if (!r.ok) {
    const texto = await r.text().catch(() => '');
    if (r.status === 404 || errorTabla(texto)) {
      if (intento === 0 && await asegurarTablas()) return enviarCodigoUsuario(req, res, cuerpo, claves, 1);
      return res.status(503).json({ error: 'La tabla vea_usuarios no existe y no se pudo crear automáticamente. Ejecute el SQL de sql/vea_usuarios.sql en Supabase.' });
    }
    return res.status(500).json({ error: 'No se pudo verificar la cuenta. Intente nuevamente.' });
  }

  const filas = await r.json().catch(() => []);
  const fila = Array.isArray(filas) && filas.length ? filas[0] : null;

  // Respuesta idéntica exista o no la cuenta (no revela quién está registrado).
  if (!fila || fila.activo === false) {
    await registrarAcceso({
      email: `cod:${email}`,
      nombre: 'Solicitud de código (sin cuenta o inactiva)',
      proveedor: 'registro',
      ip: ipDe(req),
      user_agent: userAgentDe(req),
      exito: true
    });
    return res.status(200).json({ ok: true, mensaje: MSJ_GENERICO });
  }

  const enviado = Number(fila.cod_enviado) || 0;
  if (Date.now() - enviado < COD_REENVIO_MS) {
    return res.status(429).json({ error: 'Espere un minuto antes de solicitar otro código.' });
  }

  const codigo = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  let rg;
  try {
    rg = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}`, {
      method: 'PATCH',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({
        cod_hash: hashearClave(codigo),
        cod_exp: String(Date.now() + COD_EXPIRA_MS),
        cod_fallos: 0,
        cod_enviado: String(Date.now())
      }),
      cache: 'no-store'
    });
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }
  if (!rg.ok) return res.status(500).json({ error: 'No se pudo generar el código. Intente nuevamente.' });

  const html =
    '<div style="font-family:Arial,Helvetica,sans-serif;background:#0f172a;padding:28px;color:#e2e8f0;border-radius:14px">' +
    '<p style="font-size:12px;letter-spacing:2px;color:#f59e0b;font-weight:800;margin:0 0 12px">MÓDULO VEA — RECUPERACIÓN DE CONTRASEÑA</p>' +
    '<p style="font-size:14px;margin:0 0 16px">Use el siguiente código para restablecer su contraseña. Vence en <b>10 minutos</b>.</p>' +
    '<p style="font-size:40px;font-weight:800;letter-spacing:12px;color:#fbbf24;margin:0;text-align:center;background:#1e293b;border-radius:10px;padding:16px">' + codigo + '</p>' +
    '<p style="text-align:center;margin:20px 0 4px"><a href="https://vigilancia-epidemiologica-ecru.vercel.app/login.html?recuperar=' + encodeURIComponent(email) + '" style="display:inline-block;background:#f59e0b;color:#0f172a;font-weight:800;font-size:14px;text-decoration:none;border-radius:10px;padding:12px 24px">Poner el codigo y mi contrasena nueva</a></p>' +
    '<p style="font-size:12px;color:#94a3b8;margin:14px 0 0;text-align:center">O abra el login, pulse «Recupérela aquí», escriba su correo y pegue ahí el código.</p>' +
    '<p style="font-size:12px;color:#94a3b8;margin:16px 0 0">Si usted no solicitó este código, ignore este correo: no cambió nada.</p>' +
    '</div>';

  const rc = await enviarCorreo({ para: email, asunto: 'Codigo de recuperacion - Modulo VEA', html: html });
  if (rc.error) {
    if (rc.error === 'credenciales') {
      console.error('correo: credenciales GMAIL_USER/GMAIL_APP_PASSWORD rechazadas (SMTP 535)');
      return res.status(502).json({ error: 'El servidor de correo rechazó las credenciales. Revise GMAIL_USER y GMAIL_APP_PASSWORD en Vercel.' });
    }
    console.error('correo: fallo enviando código de usuario →', rc.error, rc.detalle || '');
    return res.status(502).json({ error: 'No se pudo enviar el correo. Intente de nuevo en un minuto.' });
  }

  await registrarAcceso({
    email: `cod:${email}`,
    nombre: 'Solicitud de código de recuperación',
    proveedor: 'registro',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  return res.status(200).json({ ok: true, mensaje: MSJ_GENERICO });
}

async function restaurarConCodigoUsuario(req, res, cuerpo, claves, intento) {
  intento = intento || 0;
  const email = String(cuerpo.email || '').toLowerCase().trim().slice(0, 120);
  const codigo = String(cuerpo.codigo || '').trim();
  const claveNueva = String(cuerpo.claveNueva || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return res.status(400).json({ error: 'Correo inválido.' });
  }
  if (!/^\d{6}$/.test(codigo)) {
    return res.status(400).json({ error: 'Escriba el código de 6 dígitos recibido por correo.' });
  }
  if (claveNueva.length < 8 || claveNueva.length > 72) {
    return res.status(400).json({ error: 'La contraseña nueva debe tener entre 8 y 72 caracteres.' });
  }

  let r;
  try {
    r = await fetch(
      `${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}&select=cod_hash,cod_exp,cod_fallos&limit=1`,
      { headers: claves, cache: 'no-store' }
    );
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }

  if (!r.ok) {
    const texto = await r.text().catch(() => '');
    if (r.status === 404 || errorTabla(texto)) {
      if (intento === 0 && await asegurarTablas()) return restaurarConCodigoUsuario(req, res, cuerpo, claves, 1);
      return res.status(503).json({ error: 'La tabla vea_usuarios no existe y no se pudo crear automáticamente. Ejecute el SQL de sql/vea_usuarios.sql en Supabase.' });
    }
    return res.status(500).json({ error: 'No se pudo verificar la cuenta. Intente nuevamente.' });
  }

  const filas = await r.json().catch(() => []);
  const fila = Array.isArray(filas) && filas.length ? filas[0] : null;
  const msjSinCodigo = 'El código no existe o ya expiró. Solicite uno nuevo.';
  if (!fila || !fila.cod_hash || !(Number(fila.cod_exp) > Date.now())) {
    return res.status(400).json({ error: msjSinCodigo });
  }

  const fallos = Number(fila.cod_fallos) || 0;
  if (fallos >= COD_INTENTOS) {
    await destruirCodigo(email, claves);
    return res.status(429).json({ error: 'Código bloqueado por intentos fallidos. Solicite uno nuevo.' });
  }

  if (!verificarClave(codigo, fila.cod_hash)) {
    const nuevos = fallos + 1;
    if (nuevos >= COD_INTENTOS) {
      await destruirCodigo(email, claves);
      await registrarAcceso({
        email: `cod:${email}`,
        nombre: 'Código incorrecto (bloqueado)',
        proveedor: 'registro',
        ip: ipDe(req),
        user_agent: userAgentDe(req),
        exito: false
      });
      return res.status(429).json({ error: 'Código bloqueado por intentos fallidos. Solicite uno nuevo.' });
    }
    await incrementarFallosCodigo(email, nuevos, claves);
    return res.status(401).json({ error: `Código incorrecto. Quedan ${COD_INTENTOS - nuevos} intento(s).` });
  }

  let rg;
  try {
    rg = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}`, {
      method: 'PATCH',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({
        password_hash: hashearClave(claveNueva),
        debe_cambiar: false,
        cod_hash: '',
        cod_exp: '0',
        cod_fallos: 0,
        cod_enviado: '0'
      }),
      cache: 'no-store'
    });
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }
  if (!rg.ok) return res.status(500).json({ error: 'No se pudo guardar la contraseña. Intente nuevamente.' });

  await registrarAcceso({
    email: email,
    nombre: 'Restableció su contraseña con código por correo',
    proveedor: 'registro',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  return res.status(200).json({ ok: true });
}

async function destruirCodigo(email, claves) {
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}`, {
      method: 'PATCH',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ cod_hash: '', cod_exp: '0', cod_fallos: 0 }),
      cache: 'no-store'
    });
  } catch (_) { /* el fallo se reintenta en el próximo intento */ }
}

async function incrementarFallosCodigo(email, nuevos, claves) {
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}`, {
      method: 'PATCH',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ cod_fallos: nuevos }),
      cache: 'no-store'
    });
  } catch (_) { /* el fallo se reintenta en el próximo intento */ }
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
  if (accion === 'cambiarPropia') return cambiarClavePropia(req, res, cuerpo, claves);
  if (accion === 'enviarCodigoUsuario') return enviarCodigoUsuario(req, res, cuerpo, claves);
  if (accion === 'restaurarConCodigoUsuario') return restaurarConCodigoUsuario(req, res, cuerpo, claves);
  return res.status(400).json({ error: 'Acción inválida (use "registro", "ingreso", "usuarios", "restaurar", "cambiarPropia", "enviarCodigoUsuario" o "restaurarConCodigoUsuario").' });
};
