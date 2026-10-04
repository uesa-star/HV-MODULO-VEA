/**
 * VEA — Acceso de administración (usuario + contraseña).
 * POST /api/auth/adm
 *   { usuario, clave }              → crea cookie vea_adm (8 h, versión de sesión).
 *   { accion:'cambiar', email, claveActual, claveNueva }
 *                                    → cambia la contraseña propia (requiere sesión ADM);
 *                                      invalida todas las sesiones ADM previas.
 *   { accion:'restaurar', claveNueva }
 *                                    → lo restablece quien tiene sesión Google con el
 *                                      mismo correo registrado («Olvidé mi contraseña»);
 *                                      también invalida sesiones ADM previas.
 *   { accion:'enviarCodigo' }        → envía un código de 6 dígitos al correo del ADM
 *                                      (respaldo cuando no hay sesión Google; máx. 1/min).
 *   { accion:'restaurarConCodigo', codigo, claveNueva }
 *                                    → restablece con el código recibido por correo
 *                                      (vence a los 10 min, máx. 5 intentos).
 * DELETE /api/auth/adm → cierra la sesión ADM.
 *
 * Seguridad:
 *  · Contraseña maestra VEA_ADM_PASS (Vercel) + contraseña propia (vea_config, scrypt).
 *  · Bloqueo tras 5 intentos fallidos durante 15 minutos (anti fuerza bruta).
 *  · Cookies ADM con versión de sesión: cambiar/restablecer la clave las invalida a todas.
 *  · Código por correo: hash scrypt en vea_config, nunca se guarda ni registra en claro.
 */
const crypto = require('crypto');
const { firmar, sesion, sesionAdm, nuevoSid, cookie, ipDe, userAgentDe, NOMBRE_ADM } = require('../../lib/session');
const { hashearClave, verificarClave } = require('../../lib/clave');
const { enviarCorreo } = require('../../lib/correo');
const {
  clavesSupabase, leerConfig, guardarConfig, admActivo, tokenSesion, marcarSalida,
  FALLOS_ADM, MINUTOS_BLOQUEO, minutosRestantes
} = require('../../lib/control');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';
const LLAVES_CFG = [
  'adm_password_hash', 'adm_email', 'adm_ses', 'adm_fallos', 'adm_bloqueo_hasta',
  'adm_cod_hash', 'adm_cod_exp', 'adm_cod_fallos', 'adm_cod_enviado'
];

const COD_EXPIRA_MS = 10 * 60000;   // 10 minutos de vigencia
const COD_INTENTOS = 5;             // intentos por código
const COD_REENVIO_MS = 60000;       // 1 minuto entre envíos

function iguales(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
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

async function cambiarClaveAdm(req, res, cuerpo) {
  if (!(await admActivo(req))) return res.status(401).json({ error: 'Requiere ingreso ADM.' });

  const email = String(cuerpo.email || '').toLowerCase().trim().slice(0, 120);
  const claveActual = String(cuerpo.claveActual || '');
  const claveNueva = String(cuerpo.claveNueva || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return res.status(400).json({ error: 'Correo inválido.' });
  }
  if (claveNueva.length < 8 || claveNueva.length > 72) {
    return res.status(400).json({ error: 'La contraseña nueva debe tener entre 8 y 72 caracteres.' });
  }

  const lectura = await leerConfig(LLAVES_CFG);
  if (lectura.error) return res.status(503).json({ error: lectura.error });
  const cfg = lectura.cfg;

  const esMaestra = Boolean(process.env.VEA_ADM_PASS) && iguales(claveActual, process.env.VEA_ADM_PASS);
  const esPropia = Boolean(cfg.adm_password_hash) && verificarClave(claveActual, cfg.adm_password_hash);
  if (!esMaestra && !esPropia) {
    return res.status(401).json({ error: 'La contraseña actual es incorrecta.' });
  }

  const guardado = await guardarConfig({
    adm_password_hash: hashearClave(claveNueva),
    adm_email: email,
    adm_ses: tokenSesion(),          // invalida todas las sesiones ADM previas (C)
    adm_fallos: '0',
    adm_bloqueo_hasta: '0'
  });
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

  const lectura = await leerConfig(LLAVES_CFG);
  if (lectura.error) return res.status(503).json({ error: lectura.error });
  const cfg = lectura.cfg;

  if (!cfg.adm_email) {
    return res.status(400).json({
      error: 'Aún no registró su correo de administrador. Ingrese con la contraseña maestra y en «Mi contraseña» defina su clave y correo.'
    });
  }
  if (String(s.email).toLowerCase() !== String(cfg.adm_email).toLowerCase()) {
    return res.status(403).json({
      error: `Su sesión actual (${s.email}) no corresponde a la cuenta Google del administrador. Inicie sesión con la cuenta registrada.`
    });
  }

  const guardado = await guardarConfig({
    adm_password_hash: hashearClave(claveNueva),
    adm_ses: tokenSesion(),          // invalida sesiones ADM previas (C)
    adm_fallos: '0',
    adm_bloqueo_hasta: '0'
  });
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

async function enviarCodigoAdm(req, res) {
  if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
    return res.status(503).json({ error: 'El servicio de correo aún no está configurado en el servidor.' });
  }

  const lectura = await leerConfig(LLAVES_CFG);
  if (lectura.error) return res.status(503).json({ error: lectura.error });
  const cfg = lectura.cfg;

  if (!cfg.adm_email) {
    return res.status(400).json({
      error: 'Aún no registró su correo de administrador. Ingrese con la contraseña maestra y en «Mi contraseña» defina su clave y correo.'
    });
  }
  const enviado = Number(cfg.adm_cod_enviado) || 0;
  if (Date.now() - enviado < COD_REENVIO_MS) {
    return res.status(429).json({ error: 'Espere un minuto antes de solicitar otro código.' });
  }

  const codigo = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const guardado = await guardarConfig({
    adm_cod_hash: hashearClave(codigo),
    adm_cod_exp: String(Date.now() + COD_EXPIRA_MS),
    adm_cod_fallos: '0',
    adm_cod_enviado: String(Date.now())
  });
  if (!guardado) return res.status(503).json({ error: 'No se pudo generar el código. Intente nuevamente.' });

  const html =
    '<div style="font-family:Arial,Helvetica,sans-serif;background:#0f172a;padding:28px;color:#e2e8f0;border-radius:14px">' +
    '<p style="font-size:12px;letter-spacing:2px;color:#f59e0b;font-weight:800;margin:0 0 12px">MÓDULO VEA — RECUPERACIÓN DE CONTRASEÑA</p>' +
    '<p style="font-size:14px;margin:0 0 16px">Use el siguiente código para restablecer la contraseña de administrador. Vence en <b>10 minutos</b>.</p>' +
    '<p style="font-size:40px;font-weight:800;letter-spacing:12px;color:#fbbf24;margin:0;text-align:center;background:#1e293b;border-radius:10px;padding:16px">' + codigo + '</p>' +
    '<p style="font-size:12px;color:#94a3b8;margin:16px 0 0">Si usted no solicitó este código, ignore este correo: no cambió nada.</p>' +
    '</div>';

  const r = await enviarCorreo({ para: cfg.adm_email, asunto: 'Codigo de recuperacion - Modulo VEA', html: html });
  if (r.error) {
    if (r.error === 'credenciales') {
      console.error('correo: credenciales GMAIL_USER/GMAIL_APP_PASSWORD rechazadas (SMTP 535)');
      return res.status(502).json({ error: 'El servidor de correo rechazó las credenciales. Revise GMAIL_USER y GMAIL_APP_PASSWORD en Vercel.' });
    }
    console.error('correo: fallo enviando código →', r.error, r.detalle || '');
    return res.status(502).json({ error: 'No se pudo enviar el correo. Intente de nuevo en un minuto.' });
  }

  await registrarAcceso({
    email: 'adm:solicitó código por correo',
    nombre: 'Administrador',
    proveedor: 'adm',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  return res.status(200).json({
    ok: true,
    mensaje: 'Código enviado al correo del administrador. Vence en 10 minutos.'
  });
}

async function restaurarConCodigoAdm(req, res, cuerpo) {
  const codigo = String(cuerpo.codigo || '').trim();
  const claveNueva = String(cuerpo.claveNueva || '');
  if (!/^\d{6}$/.test(codigo)) {
    return res.status(400).json({ error: 'Escriba el código de 6 dígitos recibido por correo.' });
  }
  if (claveNueva.length < 8 || claveNueva.length > 72) {
    return res.status(400).json({ error: 'La contraseña nueva debe tener entre 8 y 72 caracteres.' });
  }

  const lectura = await leerConfig(LLAVES_CFG);
  if (lectura.error) return res.status(503).json({ error: lectura.error });
  const cfg = lectura.cfg;

  if (!cfg.adm_cod_hash || !(Number(cfg.adm_cod_exp) > Date.now())) {
    return res.status(400).json({ error: 'El código no existe o ya expiró. Solicite uno nuevo.' });
  }
  const fallos = Number(cfg.adm_cod_fallos) || 0;
  if (fallos >= COD_INTENTOS) {
    await guardarConfig({ adm_cod_hash: '', adm_cod_exp: '0', adm_cod_fallos: '0' });
    return res.status(429).json({ error: 'Código bloqueado por intentos fallidos. Solicite uno nuevo.' });
  }

  if (!verificarClave(codigo, cfg.adm_cod_hash)) {
    const nuevos = fallos + 1;
    if (nuevos >= COD_INTENTOS) {
      await guardarConfig({ adm_cod_hash: '', adm_cod_exp: '0', adm_cod_fallos: '0' });
      await registrarAcceso({
        email: 'adm:código incorrecto (bloqueado)',
        nombre: 'Intento de acceso ADM',
        proveedor: 'adm',
        ip: ipDe(req),
        user_agent: userAgentDe(req),
        exito: false
      });
      return res.status(429).json({ error: 'Código bloqueado por intentos fallidos. Solicite uno nuevo.' });
    }
    await guardarConfig({ adm_cod_fallos: String(nuevos) });
    return res.status(401).json({ error: `Código incorrecto. Quedan ${COD_INTENTOS - nuevos} intento(s).` });
  }

  const guardado = await guardarConfig({
    adm_password_hash: hashearClave(claveNueva),
    adm_ses: tokenSesion(),          // invalida sesiones ADM previas (C)
    adm_fallos: '0',
    adm_bloqueo_hasta: '0',
    adm_cod_hash: '',
    adm_cod_exp: '0',
    adm_cod_fallos: '0',
    adm_cod_enviado: '0'
  });
  if (!guardado) {
    return res.status(503).json({ error: 'No se pudo guardar la contraseña. Intente nuevamente.' });
  }

  await registrarAcceso({
    email: 'adm:restableció su contraseña con código por correo',
    nombre: 'Administrador',
    proveedor: 'adm',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  return res.status(200).json({ ok: true });
}

module.exports = async function handler(req, res) {
  if (req.method === 'DELETE') {
    const sa = sesionAdm(req);
    if (sa && sa.sid) await marcarSalida(sa.sid);
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
  if (accion === 'enviarCodigo') return enviarCodigoAdm(req, res);
  if (accion === 'restaurarConCodigo') return restaurarConCodigoAdm(req, res, cuerpo);

  const usuario = String(cuerpo.usuario || '');
  const clave = String(cuerpo.clave || '');

  // Config para: bloqueo de intentos, contraseña propia y versión de sesión.
  const lecturaCfg = await leerConfig(LLAVES_CFG);
  const cfg = lecturaCfg.cfg || {};   // sin config legible: degradar (solo maestra)

  const ahora = Date.now();
  const hasta = Number(cfg.adm_bloqueo_hasta || 0);
  if (hasta > ahora) {
    return res.status(429).json({
      error: `Demasiados intentos fallidos. Su cuenta está bloqueada durante ${minutosRestantes(hasta)} minuto(s).`
    });
  }

  let valido = usuario.length > 0 && clave.length > 0 &&
    iguales(usuario, usuarioEsperado) && iguales(clave, claveEsperada);

  if (!valido && usuario.length > 0 && clave.length > 0 &&
      iguales(usuario, usuarioEsperado) && cfg.adm_password_hash) {
    valido = verificarClave(clave, cfg.adm_password_hash);
  }

  if (!valido) {
    const fallos = (Number(cfg.adm_fallos) || 0) + 1;
    const pares = { adm_fallos: String(fallos) };
    if (fallos >= FALLOS_ADM) {
      pares.adm_fallos = '0';
      pares.adm_bloqueo_hasta = String(ahora + MINUTOS_BLOQUEO * 60000);
    }
    await guardarConfig(pares);
    await registrarAcceso({
      email: `adm:${usuario.slice(0, 60) || '(vacío)'}`,
      nombre: 'Intento de acceso ADM',
      proveedor: 'adm',
      ip: ipDe(req),
      user_agent: userAgentDe(req),
      exito: false
    });
    if (fallos >= FALLOS_ADM) {
      return res.status(429).json({
        error: `Demasiados intentos fallidos. Su cuenta está bloqueada durante ${MINUTOS_BLOQUEO} minutos.`
      });
    }
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }

  if ((Number(cfg.adm_fallos) || 0) > 0 || hasta > 0) {
    await guardarConfig({ adm_fallos: '0', adm_bloqueo_hasta: '0' });
  }

  const sid = nuevoSid();
  await registrarAcceso({
    email: `adm:${usuarioEsperado}`,
    nombre: 'Administrador',
    proveedor: 'adm',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true,
    sesion_id: sid
  });

  const token = firmar({
    email: `adm:${usuarioEsperado}`,
    nombre: 'Administrador',
    proveedor: 'adm',
    v: cfg.adm_ses || '',            // versión de sesión (C)
    sid: sid                         // id de sesión (permanencia en el log)
  }, 8);
  res.setHeader('Set-Cookie', cookie(NOMBRE_ADM, token, 8));
  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).json({ ok: true });
};
