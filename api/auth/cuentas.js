/**
 * VEA — Cuentas propias: registro e ingreso con usuario y contraseña.
 * POST /api/auth/cuentas
 *   { accion: 'registro', nombre, usuario, clave, confirm } → crea la cuenta
 *        en public.vea_usuarios (hash scrypt) DESACTIVADA: el ADM la activa
 *        desde el panel; no devuelve sesión hasta la activación.
 *   { accion: 'ingreso', usuario, clave } → valida y devuelve vea_session (12 h).
 *        Si la cuenta tiene debe_cambiar (clave temporal puesta por el ADM),
 *        responde { debe_cambiar: true } y el cliente obliga a cambiarla.
 *        Cuenta inactiva → 403 { pendiente:true, correo, nombre, institucion }:
 *        el servidor avisa AUTÁMATICAMENTE al ADM por correo (cfg.adm_email,
 *        máx. 1 cada 10 min por cuenta, con enlace de activación) y el login
 *        muestra un solo mensaje: «Su cuenta está desactivada. Pronto el
 *        administrador se comunicará con usted. Gracias.» (sin botones).
 *   GET  /api/auth/cuentas?activar=<token> → activa la cuenta al instante
 *        (firma HMAC + caduca 24 h), avisa por correo al usuario y devuelve
 *        una página de confirmación.
 *   { accion: 'cambiarPropia', claveActual, claveNueva } → el usuario con
 *        sesión propia cambia su contraseña y quita la marca debe_cambiar.
 *   { accion: 'enviarCodigoUsuario', email } → envía código de 6 dígitos al
 *        correo del usuario (recuperación "olvidé mi contraseña"; máx. 3/15 min).
 *   { accion: 'restaurarConCodigoUsuario', email, codigo, claveNueva }
 *        → restablece con el código recibido (vence 10 min, máx. 5 intentos).
 *   { accion: 'editar', email, nombre, celular, nuevoEmail } → el ADM
 *        corrige los datos de una cuenta, incluido el correo si el usuario
 *        se equivocó al registrarse (nuevoEmail debe ser único).
 *        La sesión que use el correo antiguo se cierra sola al no encontrarlo.
 *   { accion: 'estado', email, activo } → el ADM activa o desactiva
 *        una cuenta (desactivada no puede ingresar; requiere sesión ADM).
 *        Al activarla avisa por correo al usuario.
 *   { accion: 'avisar', email } → reenvía al usuario el correo «Su cuenta
 *        está activada» (requiere sesión ADM; solo cuentas activas).
 *   { accion: 'eliminar', email } → el ADM elimina una cuenta
 *        (requiere sesión ADM; el historial del log se conserva).
 */
const crypto = require('crypto');
const { firmar, cookie, sesion, ipDe, userAgentDe, nuevoSid, NOMBRE_SESION } = require('../../lib/session');
const { hashearClave, verificarClave, claveFalsa } = require('../../lib/clave');
const { enviarCorreo } = require('../../lib/correo');
const { asegurarTablas } = require('../../lib/tablas');
const { admActivo, leerConfig, guardarConfig, FALLOS_USUARIO, MINUTOS_BLOQUEO, textoSeguro } = require('../../lib/control');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';
const COD_EXPIRA_MS = 10 * 60 * 1000;   // el código de recuperación vence a los 10 min
const COD_INTENTOS = 5;                 // intentos fallidos antes de destruir el código
const COD_REENVIO_MS = 60 * 1000;       // 1 envío como mínimo por minuto
const COD_ENVIOS_MAX = 3;               // máx. 3 envíos por correo cada 15 min
const DIAS_CLAVE = 90;                  // la contraseña vence a los 90 días
const AVISO_CLAVE_DIAS = 7;             // avisar 7 días antes del vencimiento
const PROFESIONES_VALIDAS = new Set([
  'Médico', 'Enfermería', 'Obstetricia', 'Odontología', 'Psicología',
  'Tecnología médica', 'Laboratorio', 'Farmacia', 'Técnico en enfermería',
  'Administrativo', 'Otro'
]);
const TIPOS_DOCUMENTO = new Set(['DNI', 'CE', 'PASAPORTE']);
const NACIONALIDADES_VALIDAS = new Set(['Peruana', 'Venezolana', 'Colombiana', 'Ecuatoriana', 'Boliviana', 'Otra']);
const TERMINOS_VERSION = 'VEA-REGISTRO-2026-01';
const BASE_URL = 'https://vigilancia-epidemiologica-ecru.vercel.app';
const LLAVE_ADM_EMAIL = 'adm_email';
const LLAVE_SOL = 'activacion_sol';
const ACT_VENCE_MS = 24 * 60 * 60 * 1000;  // el enlace de activación vive 24 h
const SOL_REENVIO_MS = 10 * 60 * 1000;     // 1 correo al ADM cada 10 min por cuenta

/* Enlace de activación firmado: <expira>.<email en base64url>.<HMAC-SHA256>. */
function tokenActivacion(email) {
  const exp = Date.now() + ACT_VENCE_MS;
  const cuerpo = exp + '.' + Buffer.from(String(email).toLowerCase(), 'utf8').toString('base64url');
  const firma = crypto.createHmac('sha256', process.env.VEA_AUTH_SECRET).update('vea-activar:' + cuerpo).digest('base64url');
  return cuerpo + '.' + firma;
}

function leerTokenActivacion(token) {
  const partes = String(token || '').split('.');
  if (partes.length !== 3) return null;
  const cuerpo = partes[0] + '.' + partes[1];
  const espera = crypto.createHmac('sha256', process.env.VEA_AUTH_SECRET).update('vea-activar:' + cuerpo).digest('base64url');
  const a = Buffer.from(partes[2]);
  const b = Buffer.from(espera);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const exp = Number(partes[0]);
  if (!Number.isFinite(exp) || exp < Date.now()) return null;
  let email = '';
  try { email = Buffer.from(partes[1], 'base64url').toString('utf8'); } catch (_) { return null; }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return null;
  return email.toLowerCase();
}

function validarRegistro(nombre, email, celular, profesion, institucion, tipoDocumento, numeroDocumento) {
  if (!/^[\p{L}]+(?:[ .'-][\p{L}]+)+$/u.test(nombre)) {
    return 'Escriba nombres y apellidos reales, usando solo letras (por ejemplo: Ana Pérez).';
  }
  if (celular && !/^9\d{8}$/.test(celular)) {
    return 'El celular debe tener 9 dígitos y comenzar con 9.';
  }
  if (!PROFESIONES_VALIDAS.has(profesion)) {
    return 'Seleccione una profesión válida de la lista.';
  }
  if (!/^[\p{L}0-9][\p{L}0-9 .,'&/()-]{2,119}$/u.test(institucion) ||
      !/[\p{L}]{2}/u.test(institucion)) {
    return 'Escriba el nombre real de la institución donde labora.';
  }
  if (tipoDocumento === 'DNI' && !/^\d{8}$/.test(numeroDocumento)) return 'El DNI debe tener exactamente 8 dígitos.';
  if (tipoDocumento === 'CE' && !/^\d{9}$/.test(numeroDocumento)) return 'El carné de extranjería debe tener 9 dígitos.';
  if (tipoDocumento === 'PASAPORTE' && !/^[A-Z0-9]{6,12}$/.test(numeroDocumento)) return 'El pasaporte debe tener entre 6 y 12 caracteres alfanuméricos.';
  if (!TIPOS_DOCUMENTO.has(tipoDocumento)) return 'Seleccione un tipo de documento válido.';
  return '';
}

// Política de clave: mínimo 8 caracteres, al menos una mayúscula y un número.
function claveCumplePolitica(clave) {
  return clave.length >= 8 && clave.length <= 72 &&
    /[A-Z]/.test(clave) && /[0-9]/.test(clave);
}

function claveVenceEn() {
  return new Date(Date.now() + DIAS_CLAVE * 24 * 60 * 60 * 1000).toISOString();
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
    r = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?select=usuario,nombre,nacionalidad,dni,tipo_documento,numero_documento,celular,profesion,institucion,establecimiento,terminos_version,terminos_aceptados_en,activo,debe_cambiar,creado_en&order=creado_en.desc&limit=500`, {
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
  if (!claveCumplePolitica(clave)) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos una mayúscula y un número.' });
  }

  // Se lee la versión de sesión actual para poder subirla en el mismo guardado:
  // al restablecer la clave, cualquier cookie vigente de esa cuenta queda muerta.
  let prev;
  try {
    prev = await fetch(
      `${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}&select=sesion_v&limit=1`,
      { headers: claves, cache: 'no-store' }
    );
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }
  if (!prev.ok) {
    const textoPrev = await prev.text().catch(() => '');
    if (prev.status === 404 || errorTabla(textoPrev)) {
      if (intento === 0 && await asegurarTablas()) return restaurarClave(req, res, cuerpo, claves, 1);
      return res.status(503).json({ error: 'La tabla vea_usuarios no existe y no se pudo crear automáticamente. Ejecute el SQL de sql/vea_usuarios.sql en Supabase.' });
    }
    return res.status(500).json({ error: 'No se pudo restablecer la contraseña. Intente nuevamente.' });
  }
  const previas = await prev.json().catch(() => []);
  const previa = Array.isArray(previas) && previas.length ? previas[0] : null;
  if (!previa) return res.status(404).json({ error: 'No existe una cuenta con ese correo.' });

  let r;
  try {
    r = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}`, {
      method: 'PATCH',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({
        password_hash: hashearClave(clave),
        debe_cambiar: true,
        clave_vence: claveVenceEn(),
        sesion_v: (Number(previa.sesion_v) || 0) + 1
      }),
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
  const nombre = textoSeguro(cuerpo.nombre, 80);
  const email = String(cuerpo.email || cuerpo.usuario || '').toLowerCase().trim().slice(0, 120);
  const tipoDocumento = String(cuerpo.tipoDocumento || 'DNI').trim().toUpperCase();
  const numeroDocumento = String(cuerpo.numeroDocumento || '').trim().toUpperCase().replace(/[\s-]/g, '').slice(0, 12);
  const nacionalidad = String(cuerpo.nacionalidad || '').trim();
  const establecimiento = textoSeguro(cuerpo.establecimiento || cuerpo.institucion, 120);
  const dni = tipoDocumento === 'DNI' ? numeroDocumento : '';
  const celular = String(cuerpo.celular || '').replace(/[\s()-]/g, '').slice(0, 20);
  const profesion = textoSeguro(cuerpo.profesion, 60);
  const institucion = textoSeguro(cuerpo.institucion, 120);
  const clave = String(cuerpo.clave || '');
  const confirm = String(cuerpo.confirm || cuerpo.clave || '');

  // Se valida lo que se PERSISTE (establecimiento): antes podía enviarse una
  // institución válida junto con un establecimiento malicioso que iba a BD.
  const errorRegistro = validarRegistro(nombre, email, celular, profesion, establecimiento, tipoDocumento, numeroDocumento);
  if (errorRegistro) return res.status(400).json({ error: errorRegistro });
  if (!NACIONALIDADES_VALIDAS.has(nacionalidad)) return res.status(400).json({ error: 'Seleccione una nacionalidad válida.' });
  if (establecimiento.length < 3) return res.status(400).json({ error: 'Seleccione el establecimiento donde labora.' });
  if (cuerpo.terminos !== true) return res.status(400).json({ error: 'Debe aceptar los términos y la política de privacidad.' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return res.status(400).json({ error: 'Escriba un correo electrónico válido (ej: juan.perez@hospitaldeventanilla.gob.pe).' });
  }
  if (clave.length < 8 || clave.length > 72) {
    return res.status(400).json({ error: 'La contraseña debe tener entre 8 y 72 caracteres.' });
  }
  if (!claveCumplePolitica(clave)) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos una mayúscula y un número.' });
  }
  if (clave !== confirm) return res.status(400).json({ error: 'Las contraseñas no coinciden.' });

  let r;
  try {
    r = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios`, {
      method: 'POST',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({ usuario: email, nombre, nacionalidad, dni, tipo_documento: tipoDocumento, numero_documento: numeroDocumento, celular, profesion, institucion: establecimiento, establecimiento, terminos_version: TERMINOS_VERSION, terminos_aceptados_en: new Date().toISOString(), password_hash: hashearClave(clave), activo: false }),
      cache: 'no-store'
    });
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }

  if (!r.ok) {
    const texto = await r.text().catch(() => '');
    if (texto.includes('vea_usuarios_dni_unq') || texto.includes('vea_usuarios_documento_unq')) {
      return res.status(409).json({ error: 'Ese documento ya está registrado en otra cuenta.' });
    }
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

  // La cuenta nace DESACTIVADA: el ADM la activa desde el panel (punto 2 auditoría).
  // No se crea sesión: el usuario debe esperar la activación para ingresar.
  await registrarAcceso({
    email,
    nombre,
    proveedor: 'registro',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  // Aviso inmediato al ADM para activación rápida. Nunca bloquea el registro.
  try {
    if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
      const lectura = await leerConfig(['adm_email']);
      const paraAdm = lectura && lectura.cfg ? String(lectura.cfg.adm_email || '').trim() : '';
      if (paraAdm) {
        const esc = (s) => String(s || '—').replace(/[<>&"']/g, (m) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[m]));
        const rc = await enviarCorreo({
          para: paraAdm,
          asunto: 'Nueva cuenta por activar - Modulo VEA',
          html:
            '<div style="font-family:Arial,Helvetica,sans-serif;background:#0f172a;padding:28px;color:#e2e8f0;border-radius:14px">' +
            '<p style="font-size:12px;letter-spacing:2px;color:#f59e0b;font-weight:800;margin:0 0 12px">MÓDULO VEA — NUEVA CUENTA POR ACTIVAR</p>' +
            '<p style="font-size:14px;margin:0 0 16px">Se registró un usuario. Actívelo desde el panel ADM → Cuentas de usuarios.</p>' +
            '<table style="font-size:13px;border-collapse:collapse">' +
             '<tr><td style="color:#94a3b8;padding:4px 12px 4px 0">Nombre</td><td><b>' + esc(nombre) + '</b></td></tr>' +
             '<tr><td style="color:#94a3b8;padding:4px 12px 4px 0">DNI</td><td><b>' + esc(dni) + '</b></td></tr>' +
             '<tr><td style="color:#94a3b8;padding:4px 12px 4px 0">Correo</td><td><b>' + esc(email) + '</b></td></tr>' +
            '<tr><td style="color:#94a3b8;padding:4px 12px 4px 0">Celular</td><td><b>' + esc(celular) + '</b></td></tr>' +
            '<tr><td style="color:#94a3b8;padding:4px 12px 4px 0">Profesión</td><td><b>' + esc(profesion) + '</b></td></tr>' +
            '<tr><td style="color:#94a3b8;padding:4px 12px 4px 0">Institución</td><td><b>' + esc(institucion) + '</b></td></tr>' +
            '</table>' +
            '<p style="margin:20px 0 4px"><a href="https://vigilancia-epidemiologica-ecru.vercel.app/?adm=1" style="display:inline-block;background:#f59e0b;color:#0f172a;font-weight:800;font-size:14px;text-decoration:none;border-radius:10px;padding:12px 24px">Abrir panel ADM</a></p>' +
            '</div>'
        });
        if (!rc.error) {
          await registrarAcceso({
            email: `adm:avisó nueva cuenta → ${email}`,
            nombre: nombre,
            proveedor: 'adm',
            ip: ipDe(req),
            user_agent: userAgentDe(req),
            exito: true
          });
        }
      }
    }
  } catch (_) { /* el aviso nunca bloquea el registro */ }

  return res.status(200).json({
    ok: true,
    pendiente: true,
    mensaje: 'Cuenta creada. Está pendiente de activación por el administrador; intente ingresar luego.'
  });
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
      `${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(usuario)}&select=nombre,institucion,password_hash,activo,debe_cambiar,sesion_v&limit=1`,
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

  if (!fila || !correcta) {
    await registrarAcceso({
      email: `registro:${textoSeguro(usuario, 60) || '(vacío)'}`,
      nombre: 'Intento de acceso con usuario/contraseña',
      proveedor: 'registro',
      ip: ipDe(req),
      user_agent: userAgentDe(req),
      exito: false
    });
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }

  if (!activo) {
    // Aviso automático al ADM (correo con enlace de activación, 1 cada 10 min).
    const aviso = await avisarActivacion(usuario, fila.nombre || '', fila.institucion || '', claves);
    await registrarAcceso({
      email: `registro:${textoSeguro(usuario, 60) || '(vacío)'}`,
      nombre: aviso.correo ? 'Cuenta pendiente de activación (aviso al ADM)' : 'Cuenta pendiente de activación',
      proveedor: 'registro',
      ip: ipDe(req),
      user_agent: userAgentDe(req),
      exito: false
    });
    return res.status(403).json({
      error: 'Su cuenta está desactivada. Pronto el administrador se comunicará con usted. Gracias.',
      pendiente: true,
      correo: aviso.correo,
      nombre: fila.nombre || '',
      institucion: fila.institucion || ''
    });
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
  const datosToken = { email: usuario, nombre: fila.nombre || usuario, proveedor: 'registro', sid: sidIng, sv: Number(fila.sesion_v) || 0 };
  if (debeCambiar) datosToken.dc = 1;
  const token = firmar(datosToken, 12);
  res.setHeader('Set-Cookie', cookie(NOMBRE_SESION, token, 12));
  let avisoClave = null;
  if (fila.clave_vence) {
    const dias = Math.ceil((new Date(fila.clave_vence).getTime() - Date.now()) / (24 * 60 * 60 * 1000));
    if (dias <= 0) avisoClave = 'Su contraseña venció. Cámbiela desde «Mi contraseña».';
    else if (dias <= AVISO_CLAVE_DIAS) avisoClave = 'Su contraseña vence en ' + dias + ' día(s). Cámbiela desde «Mi contraseña».';
  }
  return res.status(200).json({ ok: true, debe_cambiar: debeCambiar, aviso_clave: avisoClave });
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
  if (!claveCumplePolitica(nueva)) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos una mayúscula y un número.' });
  }

  let r;
  try {
    r = await fetch(
      `${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(usuario)}&select=password_hash,activo,sesion_v&limit=1`,
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
  if (fila.activo === false) {
    return res.status(403).json({ error: 'La cuenta está desactivada. Contacte al administrador.' });
  }
  if (!verificarClave(actual, fila.password_hash)) {
    return res.status(401).json({ error: 'La contraseña actual es incorrecta.' });
  }

  let r2;
  try {
    r2 = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(usuario)}`, {
      method: 'PATCH',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({
        password_hash: hashearClave(nueva),
        debe_cambiar: false,
        clave_vence: claveVenceEn(),
        // Sube la versión de sesión: mata las cookies vigentes de esta cuenta
        // (la nueva cookie de abajo ya lleva el número nuevo).
        sesion_v: (Number(fila.sesion_v) || 0) + 1
      }),
      cache: 'no-store'
    });
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }
  if (!r2.ok) return res.status(500).json({ error: 'No se pudo guardar la nueva contraseña. Intente nuevamente.' });

  const filasG = await r2.json().catch(() => []);
  const filaG = Array.isArray(filasG) && filasG.length ? filasG[0] : null;
  const nuevaSv = filaG ? (Number(filaG.sesion_v) || 0) : 0;

  await registrarAcceso({
    email: usuario,
    nombre: String(datos.nombre || usuario),
    proveedor: 'registro',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  const token = firmar({ email: usuario, nombre: datos.nombre || usuario, proveedor: 'registro', sid: datos.sid, sv: nuevaSv }, 12);
  res.setHeader('Set-Cookie', cookie(NOMBRE_SESION, token, 12));
  return res.status(200).json({ ok: true });
}

const MSJ_GENERICO = 'Si existe una cuenta con ese correo, le enviamos un código de 6 dígitos (vence en 10 minutos). Puede tardar hasta 3 minutos en llegar: revise su bandeja de entrada, Spam o Promociones.';

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

  // Respuesta idéntica si no existe la cuenta. Una cuenta inactiva también
  // puede recuperar su clave; seguirá sin poder ingresar hasta que el ADM la active.
  if (!fila) {
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
      `${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}&select=cod_hash,cod_exp,cod_fallos,sesion_v&limit=1`,
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
        cod_enviado: '0',
        // Revoca cualquier cookie vigente de esta cuenta.
        sesion_v: (Number(fila.sesion_v) || 0) + 1
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

async function editarUsuario(req, res, cuerpo, claves, intento) {
  intento = intento || 0;
  if (!(await admActivo(req))) return res.status(401).json({ error: 'Requiere ingreso ADM.' });

  const email = String(cuerpo.email || '').toLowerCase().trim().slice(0, 120);
  const nombre = textoSeguro(cuerpo.nombre, 120);
  const tipoDocumento = String(cuerpo.tipoDocumento || 'DNI').trim().toUpperCase();
  const numeroDocumento = String(cuerpo.numeroDocumento || '').trim().toUpperCase().replace(/[\s-]/g, '').slice(0, 12);
  const celular = String(cuerpo.celular || '').trim().slice(0, 30);
  const nuevoEmail = String(cuerpo.nuevoEmail || '').toLowerCase().trim().slice(0, 120);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return res.status(400).json({ error: 'Correo inválido.' });
  }
  if (nombre.length < 2) {
    return res.status(400).json({ error: 'El nombre debe tener al menos 2 caracteres.' });
  }
  if (cuerpo.numeroDocumento !== undefined && !TIPOS_DOCUMENTO.has(tipoDocumento)) {
    return res.status(400).json({ error: 'Seleccione un tipo de documento válido.' });
  }
  if (cuerpo.numeroDocumento !== undefined) {
    const errorDocumento = validarRegistro(nombre, email, celular, 'Otro', 'Hospital de Ventanilla', tipoDocumento, numeroDocumento);
    if (errorDocumento && /documento|DNI|carné|pasaporte/i.test(errorDocumento)) return res.status(400).json({ error: errorDocumento });
  }
  if (celular && !/^\+?[0-9\s()-]{7,18}$/.test(celular)) {
    return res.status(400).json({ error: 'El celular debe contener solo dígitos (7 a 15 números).' });
  }
  const cambiaCorreo = Boolean(nuevoEmail) && nuevoEmail !== email;
  if (cambiaCorreo && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(nuevoEmail)) {
    return res.status(400).json({ error: 'Correo nuevo inválido.' });
  }

  const cambios = { nombre: nombre, celular: celular };
  if (cuerpo.numeroDocumento !== undefined) {
    cambios.dni = tipoDocumento === 'DNI' ? numeroDocumento : '';
    cambios.tipo_documento = tipoDocumento;
    cambios.numero_documento = numeroDocumento;
  }
  if (cuerpo.profesion !== undefined) {
    const prof = textoSeguro(cuerpo.profesion, 60);
    if (prof.length < 2) return res.status(400).json({ error: 'Seleccione la profesión.' });
    cambios.profesion = prof;
  }
  if (cuerpo.institucion !== undefined) {
    const inst = textoSeguro(cuerpo.institucion, 120);
    if (inst.length < 2) return res.status(400).json({ error: 'Escriba la institución (mínimo 2 letras).' });
    cambios.institucion = inst;
  }
  if (cambiaCorreo) {
    cambios.usuario = nuevoEmail;
    cambios.cod_hash = '';
    cambios.cod_exp = '0';
    cambios.cod_fallos = 0;
    cambios.cod_enviado = '0';
  }

  let r;
  try {
    r = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}`, {
      method: 'PATCH',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify(cambios),
      cache: 'no-store'
    });
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }

  if (!r.ok) {
    const texto = await r.text().catch(() => '');
    if (r.status === 404 || errorTabla(texto)) {
      if (intento === 0 && await asegurarTablas()) return editarUsuario(req, res, cuerpo, claves, 1);
      return res.status(503).json({ error: 'La tabla vea_usuarios no existe y no se pudo crear automáticamente. Ejecute el SQL de sql/vea_usuarios.sql en Supabase.' });
    }
    if (r.status === 409 || texto.includes('duplicate') || texto.includes('23505')) {
      return res.status(409).json({ error: 'Ese correo ya está registrado en otra cuenta.' });
    }
    return res.status(500).json({ error: 'No se pudo guardar los cambios. Intente nuevamente.' });
  }

  const filas = await r.json().catch(() => []);
  if (!Array.isArray(filas) || !filas.length) {
    return res.status(404).json({ error: 'No existe una cuenta con ese correo.' });
  }

  const adm = await admActivo(req);
  const admDatos = adm || {};
  await registrarAcceso({
    email: cambiaCorreo ? `adm:editó cuenta ${email} → ${nuevoEmail}` : `adm:editó cuenta → ${email}`,
    nombre: String(admDatos.email || 'ADM'),
    proveedor: 'adm',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  return res.status(200).json({ ok: true, usuario: cambiaCorreo ? nuevoEmail : email });
}

async function cambiarEstadoUsuario(req, res, cuerpo, claves, intento) {
  intento = intento || 0;
  if (!(await admActivo(req))) return res.status(401).json({ error: 'Requiere ingreso ADM.' });

  const email = String(cuerpo.email || '').toLowerCase().trim().slice(0, 120);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return res.status(400).json({ error: 'Correo inválido.' });
  }
  if (cuerpo.activo !== true && cuerpo.activo !== false) {
    return res.status(400).json({ error: 'Estado inválido.' });
  }
  const activo = cuerpo.activo === true;

  // Estado anterior: si la activamos desde el panel, avisamos al usuario.
  let g;
  try {
    g = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}&select=nombre,activo&limit=1`, {
      headers: claves,
      cache: 'no-store'
    });
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }
  const antes = (await g.json().catch(() => []))[0] || null;
  if (!antes) {
    return res.status(404).json({ error: 'No existe una cuenta con ese correo.' });
  }

  let r;
  try {
    r = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}`, {
      method: 'PATCH',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: JSON.stringify({ activo: activo }),
      cache: 'no-store'
    });
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }

  if (!r.ok) {
    const texto = await r.text().catch(() => '');
    if (r.status === 404 || errorTabla(texto)) {
      if (intento === 0 && await asegurarTablas()) return cambiarEstadoUsuario(req, res, cuerpo, claves, 1);
      return res.status(503).json({ error: 'La tabla vea_usuarios no existe y no se pudo crear automáticamente. Ejecute el SQL de sql/vea_usuarios.sql en Supabase.' });
    }
    return res.status(500).json({ error: 'No se pudo cambiar el estado. Intente nuevamente.' });
  }

  const filas = await r.json().catch(() => []);
  if (!Array.isArray(filas) || !filas.length) {
    return res.status(404).json({ error: 'No existe una cuenta con ese correo.' });
  }

  const adm = await admActivo(req);
  const admDatos = adm || {};
  await registrarAcceso({
    email: `adm:${activo ? 'activó' : 'desactivó'} cuenta → ${email}`,
    nombre: String(admDatos.email || 'ADM'),
    proveedor: 'adm',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  if (activo && antes.activo === false) {
    try {
      await enviarCorreo({
        para: email,
        asunto: 'VEA - Su cuenta esta activada',
        html: plantillaUsuarioActivada(antes.nombre || '')
      });
    } catch (e) {
      console.error('correo: fallo aviso de cuenta activada →', e && e.message);
    }
  }

  return res.status(200).json({ ok: true, usuario: email, activo: activo });
}

/* Aviso manual del ADM: reenvía al usuario el correo «Su cuenta está activada». */
async function avisarUsuario(req, res, cuerpo, claves) {
  if (!(await admActivo(req))) return res.status(401).json({ error: 'Requiere ingreso ADM.' });

  const email = String(cuerpo.email || '').toLowerCase().trim().slice(0, 120);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return res.status(400).json({ error: 'Correo inválido.' });
  }

  let r;
  try {
    r = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}&select=nombre,activo&limit=1`, {
      headers: claves,
      cache: 'no-store'
    });
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }
  const filas = await r.json().catch(() => []);
  const fila = Array.isArray(filas) && filas.length ? filas[0] : null;
  if (!fila) return res.status(404).json({ error: 'No existe una cuenta con ese correo.' });
  if (fila.activo === false) {
    return res.status(400).json({ error: 'La cuenta está desactivada: actívela primero para avisarle.' });
  }

  let fallo = null;
  try {
    const rc = await enviarCorreo({
      para: email,
      asunto: 'VEA - Su cuenta esta activada',
      html: plantillaUsuarioActivada(fila.nombre || '')
    });
    if (rc.error) fallo = rc.error;
  } catch (e) {
    fallo = e && e.message;
  }
  if (fallo) {
    console.error('correo: fallo aviso manual de activación →', fallo);
    return res.status(502).json({ error: 'No se pudo enviar el correo de aviso. Intente nuevamente.' });
  }

  const adm = await admActivo(req);
  await registrarAcceso({
    email: `adm:avisó activación → ${email}`,
    nombre: String((adm || {}).email || 'ADM'),
    proveedor: 'adm',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });
  return res.status(200).json({ ok: true, usuario: email });
}

async function eliminarUsuario(req, res, cuerpo, claves, intento) {
  intento = intento || 0;
  if (!(await admActivo(req))) return res.status(401).json({ error: 'Requiere ingreso ADM.' });

  const email = String(cuerpo.email || '').toLowerCase().trim().slice(0, 120);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
    return res.status(400).json({ error: 'Correo inválido.' });
  }

  let r;
  try {
    r = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}`, {
      method: 'DELETE',
      headers: { ...claves, Prefer: 'return=representation' },
      cache: 'no-store'
    });
  } catch (_) {
    return res.status(502).json({ error: 'No se pudo contactar con la base de datos. Intente nuevamente.' });
  }

  if (!r.ok) {
    const texto = await r.text().catch(() => '');
    if (r.status === 404 || errorTabla(texto)) {
      if (intento === 0 && await asegurarTablas()) return eliminarUsuario(req, res, cuerpo, claves, 1);
      return res.status(503).json({ error: 'La tabla vea_usuarios no existe y no se pudo crear automáticamente. Ejecute el SQL de sql/vea_usuarios.sql en Supabase.' });
    }
    return res.status(500).json({ error: 'No se pudo eliminar la cuenta. Intente nuevamente.' });
  }

  const filas = await r.json().catch(() => []);
  if (!Array.isArray(filas) || !filas.length) {
    return res.status(404).json({ error: 'No existe una cuenta con ese correo.' });
  }

  const adm = await admActivo(req);
  const admDatos = adm || {};
  await registrarAcceso({
    email: `adm:eliminó cuenta → ${email}`,
    nombre: String(admDatos.email || 'ADM'),
    proveedor: 'adm',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  return res.status(200).json({ ok: true, usuario: email });
}

/* ---------- Aviso automático de activación al ADM (sin botones en el login) ---------- */
function escHtml(t) {
  return String(t || '').replace(/[&<>"]/g, function (c) {
    return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c];
  });
}

function plantillaCorreoAdm(email, nombre, institucion, link) {
  const fecha = new Date().toLocaleString('es-PE', { timeZone: 'America/Lima', dateStyle: 'short', timeStyle: 'short' });
  return '<div style="font-family:Arial,Helvetica,sans-serif;background:#0f172a;padding:28px;color:#e2e8f0;border-radius:14px">' +
    '<p style="font-size:12px;letter-spacing:2px;color:#f59e0b;font-weight:800;margin:0 0 12px">MÓDULO VEA — ACTIVACIÓN DE CUENTA</p>' +
    '<p style="font-size:14px;margin:0 0 14px">Un usuario con cuenta desactivada solicita poder ingresar:</p>' +
    '<table style="width:100%;border-collapse:collapse;font-size:13px;margin:0 0 16px">' +
    '<tr><td style="padding:7px 9px;border:1px solid #334155;background:#1e293b;font-weight:700;color:#cbd5e1">Usuario</td><td style="padding:7px 9px;border:1px solid #334155">' + escHtml(nombre || '(sin nombre)') + '</td></tr>' +
    '<tr><td style="padding:7px 9px;border:1px solid #334155;background:#1e293b;font-weight:700;color:#cbd5e1">Correo</td><td style="padding:7px 9px;border:1px solid #334155">' + escHtml(email) + '</td></tr>' +
    '<tr><td style="padding:7px 9px;border:1px solid #334155;background:#1e293b;font-weight:700;color:#cbd5e1">Institución</td><td style="padding:7px 9px;border:1px solid #334155">' + escHtml(institucion || '—') + '</td></tr>' +
    '<tr><td style="padding:7px 9px;border:1px solid #334155;background:#1e293b;font-weight:700;color:#cbd5e1">Solicitado</td><td style="padding:7px 9px;border:1px solid #334155">' + escHtml(fecha) + ' (hora Perú)</td></tr>' +
    '</table>' +
    '<p style="text-align:center;margin:6px 0 4px"><a href="' + link + '" style="display:inline-block;background:#0969da;color:#fff;font-weight:800;font-size:15px;text-decoration:none;border-radius:10px;padding:13px 26px">✅ Activar ahora</a></p>' +
    '<p style="text-align:center;margin:14px 0 4px"><a href="' + BASE_URL + '/?adm=1" style="color:#7dd3fc;font-size:13px">Abrir en el panel → Gestión de Usuarios</a></p>' +
    '<p style="font-size:12px;color:#94a3b8;margin:14px 0 0;text-align:center">El enlace caduca en 24 horas y solo activa esta cuenta.<br>También puede activarla desde el panel: Gestión de Usuarios → Activar.</p>' +
    '</div>';
}

function plantillaUsuarioActivada(nombre) {
  return '<div style="font-family:Arial,Helvetica,sans-serif;background:#0f172a;padding:28px;color:#e2e8f0;border-radius:14px">' +
    '<p style="font-size:12px;letter-spacing:2px;color:#4ade80;font-weight:800;margin:0 0 12px">MÓDULO VEA — CUENTA ACTIVADA</p>' +
    '<p style="font-size:15px;margin:0 0 10px">Hola ' + escHtml(nombre || '') + ', su cuenta ya fue <b style="color:#4ade80">activada</b>. Ya puede iniciar sesión con su correo y contraseña.</p>' +
    '<p style="text-align:center;margin:20px 0 4px"><a href="' + BASE_URL + '/login.html" style="display:inline-block;background:#16a34a;color:#fff;font-weight:800;font-size:14px;text-decoration:none;border-radius:10px;padding:12px 24px">Ir al inicio de sesión</a></p>' +
    '<p style="font-size:12px;color:#94a3b8;margin:16px 0 0;text-align:center">Si usted no esperaba este aviso, no comparta este correo.</p>' +
    '</div>';
}

/* Página de confirmación del enlace de activación (GET ?activar=). */
function paginaActivacion(ok, titulo, texto) {
  const color = ok ? '#16a34a' : '#dc2626';
  return '<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
    '<title>' + escHtml(titulo) + ' · VEA</title><style>' +
    '*{box-sizing:border-box;margin:0;padding:0}' +
    'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;background:#f7f9fc;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem 1rem;color:#1f2328}' +
    '.c{width:100%;max-width:23rem;background:#fff;border:1px solid #e3e8ef;border-top:5px solid ' + color + ';border-radius:14px;padding:26px 22px;box-shadow:0 8px 26px rgba(15,23,42,.08);text-align:center}' +
    '.m{width:3.1rem;height:3.1rem;border-radius:50%;background:#0f172a;color:#f87171;display:grid;place-items:center;margin:0 auto 14px;font-weight:900;font-size:.9rem;border:3px solid #e7ecf3}' +
    'h1{font-size:1.18rem;margin-bottom:10px;color:' + color + '}' +
    'p{font-size:.86rem;line-height:1.65;color:#4b5563;word-break:break-word}' +
    'a.b{display:inline-block;margin-top:18px;background:' + color + ';color:#fff;text-decoration:none;font-weight:800;font-size:.9rem;padding:12px 22px;border-radius:9px}' +
    '.pie{margin-top:16px;font-size:.7rem;color:#8b949e;line-height:1.6}' +
    '</style></head><body><main class="c">' +
    '<div class="m">VEA</div>' +
    '<h1>' + escHtml(titulo) + '</h1>' +
    '<p>' + escHtml(texto) + '</p>' +
    '<a class="b" href="/login.html">Ir al inicio de sesión</a>' +
    '<p class="pie">Sistema de vigilancia epidemiológica · Información sujeta a validación oficial.</p>' +
    '</main></body></html>';
}

/* Aviso automático al ADM cuando alguien con cuenta inactiva intenta ingresar:
   correo con enlace de activación (24 h), máx. 1 cada 10 min por cuenta. */
async function avisarActivacion(email, nombre, institucion, claves) {
  const correo = String(email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(correo)) return { correo: false };

  const lectura = await leerConfig([LLAVE_ADM_EMAIL, LLAVE_SOL]);
  const cfg = lectura.cfg || {};
  const link = BASE_URL + '/api/auth/cuentas?activar=' + tokenActivacion(correo);

  let sol = {};
  try { sol = JSON.parse(cfg[LLAVE_SOL] || '{}') || {}; } catch (_) { sol = {}; }
  const ahora = Date.now();
  Object.keys(sol).forEach(function (k) {
    if (!Number(sol[k]) || ahora - Number(sol[k]) > ACT_VENCE_MS) delete sol[k];
  });
  const admEmail = String(cfg[LLAVE_ADM_EMAIL] || '').trim().toLowerCase();
  const debeCorreo = (!Number(sol[correo]) || ahora - Number(sol[correo]) > SOL_REENVIO_MS) &&
    /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(admEmail);
  if (!debeCorreo) return { correo: false };

  let correoOk = false;
  try {
    const rc = await enviarCorreo({
      para: admEmail,
      asunto: 'VEA - Activar usuario - ' + correo,
      html: plantillaCorreoAdm(correo, nombre, institucion, link)
    });
    correoOk = !rc.error;
    if (rc.error) console.error('correo: fallo aviso de activación →', rc.error, rc.detalle || '');
  } catch (e) {
    console.error('correo: excepción en aviso de activación →', e && e.message);
  }
  sol[correo] = String(ahora);
  await guardarConfig({ [LLAVE_SOL]: JSON.stringify(sol) });
  return { correo: correoOk };
}

/* GET /api/auth/cuentas?activar=<token> — activa la cuenta al instante. */
async function activarConToken(req, res, token) {
  if (!process.env.VEA_AUTH_SECRET) {
    return res.status(503).send(paginaActivacion(false, 'Servicio no configurado', 'Falta VEA_AUTH_SECRET en Vercel. Contacte al soporte del sistema.'));
  }
  const email = leerTokenActivacion(token);
  if (!email) {
    return res.status(400).send(paginaActivacion(false, 'Enlace no válido', 'El enlace no es válido o venció (dura 24 horas). Solicite la activación de nuevo desde el módulo.'));
  }
  const claves = clavesSupabase();
  if (!claves) {
    return res.status(503).send(paginaActivacion(false, 'Servicio no disponible', 'Base de datos no configurada. Intente más tarde.'));
  }

  let r;
  try {
    r = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}&select=nombre,activo&limit=1`, {
      headers: claves,
      cache: 'no-store'
    });
  } catch (_) {
    return res.status(502).send(paginaActivacion(false, 'No se pudo verificar', 'No se pudo contactar con la base de datos. Intente más tarde.'));
  }
  const filas = await r.json().catch(() => []);
  const fila = Array.isArray(filas) && filas.length ? filas[0] : null;
  if (!fila) {
    return res.status(404).send(paginaActivacion(false, 'Cuenta no encontrada', 'No existe ninguna cuenta con ese correo.'));
  }
  if (fila.activo !== false) {
    return res.status(200).send(paginaActivacion(true, 'La cuenta ya estaba activada', 'La cuenta ' + email + ' ya puede ingresar normalmente.'));
  }

  let p;
  try {
    p = await fetch(`${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(email)}`, {
      method: 'PATCH',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ activo: true }),
      cache: 'no-store'
    });
  } catch (_) {
    return res.status(502).send(paginaActivacion(false, 'No se pudo activar', 'No se pudo contactar con la base de datos. Intente más tarde.'));
  }
  if (!p.ok) {
    return res.status(502).send(paginaActivacion(false, 'No se pudo activar', 'Ocurrió un error al activar la cuenta. Intente más tarde.'));
  }

  await registrarAcceso({
    email: `activacion:${email}`,
    nombre: 'Cuenta activada por enlace del correo',
    proveedor: 'registro',
    ip: ipDe(req),
    user_agent: userAgentDe(req),
    exito: true
  });

  try {
    await enviarCorreo({
      para: email,
      asunto: 'VEA - Su cuenta esta activada',
      html: plantillaUsuarioActivada(fila.nombre)
    });
  } catch (e) {
    console.error('correo: fallo aviso de cuenta activada →', e && e.message);
  }

  return res.status(200).send(paginaActivacion(true, 'Cuenta activada', 'La cuenta ' + email + ' quedó activada. Ya puede iniciar sesión con su correo y contraseña.'));
}

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'GET') {
    let tk = '';
    try { tk = new URL(req.url, 'http://local').searchParams.get('activar') || ''; } catch (_) { tk = ''; }
    if (tk) return activarConToken(req, res, tk);
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

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
  if (accion === 'editar') return editarUsuario(req, res, cuerpo, claves);
  if (accion === 'estado') return cambiarEstadoUsuario(req, res, cuerpo, claves);
  if (accion === 'avisar') return avisarUsuario(req, res, cuerpo, claves);
  if (accion === 'eliminar') return eliminarUsuario(req, res, cuerpo, claves);
  return res.status(400).json({ error: 'Acción inválida (use "registro", "ingreso", "usuarios", "restaurar", "cambiarPropia", "enviarCodigoUsuario", "restaurarConCodigoUsuario", "editar", "estado" o "eliminar").' });
};
