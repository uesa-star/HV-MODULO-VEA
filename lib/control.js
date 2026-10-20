/**
 * VEA — Control de administración compartido:
 *  · lectura/escritura de public.vea_config (auto-creable vía lib/tablas)
 *  · admActivo(req): sesión ADM válida (cookie + versión de sesión — se invalida
 *    al cambiar la contraseña, C)
 *  · contadores de intentos fallidos (bloqueo anti fuerza bruta — B)
 */
const crypto = require('crypto');
const { sesion, sesionAdm } = require('./session');
const { asegurarTablas } = require('./tablas');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';

function clavesSupabase() {
  const k = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
  return k ? { apikey: k, Authorization: `Bearer ${k}` } : null;
}

function errorTabla(texto) {
  return texto.includes('PGRST205') || texto.includes('42P01');
}

async function leerConfig(llaves, intento) {
  intento = intento || 0;
  const claves = clavesSupabase();
  if (!claves) return { error: 'Sin credenciales de base de datos en Vercel.' };
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/vea_config?k=in.(${llaves.join(',')})`, {
      headers: claves,
      cache: 'no-store'
    });
    if (r.status === 404 || r.status === 400) {
      if (intento === 0 && await asegurarTablas()) return leerConfig(llaves, 1);
      return { error: 'La tabla vea_config no existe y no se pudo crear automáticamente.' };
    }
    if (!r.ok) return { error: 'No se pudo leer la configuración. Intente nuevamente.' };
    const filas = await r.json().catch(() => []);
    const cfg = {};
    (Array.isArray(filas) ? filas : []).forEach(function (f) { cfg[String(f.k)] = String(f.v || ''); });
    return { cfg };
  } catch (_) {
    return { error: 'No se pudo contactar con la base de datos.' };
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

/**
 * Kill-switch de sesiones («desconectar a todos»): al subir el valor de
 * `sesion_global_v` en public.vea_config, TODAS las cookies firmadas antes
 * quedan invalidadas al instante — sin rotar VEA_AUTH_SECRET ni redeploy.
 * El valor es monótono: solo sube (bajarlo revalidaría cookies viejas).
 * Si la configuración no es legible devuelve null y no se aplica el corte,
 * para no dejar a todo el personal fuera por un fallo transitorio de la base.
 */
const CLAVE_EPOCH_SESION = 'sesion_global_v';

async function leerEpochSesion() {
  const lectura = await leerConfig([CLAVE_EPOCH_SESION]);
  if (!lectura || lectura.error || !lectura.cfg) return null;
  const n = Number.parseInt(String(lectura.cfg[CLAVE_EPOCH_SESION] || '0').trim(), 10);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

function epochValido(valor) {
  const n = Number.parseInt(String(valor == null ? '0' : valor).trim(), 10);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

async function admActivo(req) {
  const datos = sesionAdm(req);
  if (!datos) return null;
  const lectura = await leerConfig(['adm_ses', CLAVE_EPOCH_SESION]);
  // Falla cerrada: si la configuración no es legible NO se acepta la sesión
  // (antes se degradaba y se aceptaba, saltándose la invalidación por clave).
  if (lectura.error || !lectura.cfg) return null;
  const version = lectura.cfg.adm_ses;
  if (version && String(datos.v || '') !== version) return null; // sesión de antes del cambio de clave
  if (epochValido(datos.gv) !== epochValido(lectura.cfg[CLAVE_EPOCH_SESION])) return null; // kill-switch global
  return datos;
}

/**
 * Sesión de usuario vigente: cookie válida + dominio Google permitido +
 * cuenta existente/activa + versión de sesión sin cambiar.
 * Devuelve { ok:true, datos } o { ok:false, status, error }.
 * Usada por /api/app, /api/vea-data y /api/alerts para que una cuenta
 * desactivada, eliminada o con clave restablecida pierda acceso de inmediato
 * aunque su cookie siga siendo criptográficamente válida.
 */
async function sesionActiva(req) {
  const datos = sesion(req);
  if (!datos) return { ok: false, status: 401, error: 'No autenticado' };
  // Kill-switch global: si el ADM subió sesion_global_v, toda sesión emitida
  // antes deja de valer de inmediato (Google y registro por igual).
  const epoch = await leerEpochSesion();
  if (epoch !== null && epochValido(datos.gv) !== epoch) {
    return { ok: false, status: 401, error: 'Sesión revocada por el administrador' };
  }
  if (datos.proveedor === 'google' && !correoGooglePermitido(datos.email)) {
    return { ok: false, status: 401, error: 'Sesión no válida' };
  }
  if (datos.proveedor === 'registro' && datos.email) {
    // Si la cuenta NO se puede verificar (sin llaves, error de red o de
    // consulta) se DENIEGA: nunca se asume que está activa (A-1 fail-closed).
    const claves = clavesSupabase();
    if (!claves) return { ok: false, status: 401, error: 'Cuenta no verificable' };
    try {
      const rq = await fetch(
        `${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(String(datos.email).toLowerCase())}` +
        `&select=activo,sesion_v&limit=1`,
        { headers: claves, cache: 'no-store' }
      );
      const fr = rq.ok ? await rq.json().catch(() => null) : null;
      const fu = Array.isArray(fr) && fr.length ? fr[0] : null;
      if (!fu || fu.activo === false) return { ok: false, status: 401, error: 'Cuenta desactivada' };
      if (Number(fu.sesion_v) !== Number(datos.sv || 0)) {
        return { ok: false, status: 401, error: 'Sesión revocada por cambio de contraseña' };
      }
    } catch (_) {
      return { ok: false, status: 401, error: 'No se pudo verificar la cuenta' };
    }
  }
  return { ok: true, datos };
}

/**
 * Texto seguro para guardar en BD y pintar en el panel ADM:
 * sin caracteres de control ni etiquetas HTML (< >).
 */
function textoSeguro(valor, largo) {
  return String(valor == null ? '' : valor)
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/[<>]/g, '')
    .trim()
    .slice(0, largo || 120);
}

function tokenSesion() {
  return crypto.randomBytes(16).toString('hex');
}

/** Marca la última actividad de una sesión en vea_login_log (para «permanencia»). */
async function marcarVisto(sid) {
  if (!sid) return;
  const claves = clavesSupabase();
  if (!claves) return;
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/vea_login_log?sesion_id=eq.${encodeURIComponent(sid)}&salida=is.null`, {
      method: 'PATCH',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ ultimo_visto: new Date().toISOString() }),
      cache: 'no-store'
    });
  } catch (_) { /* la actividad nunca bloquea */ }
}

/**
 * Registra el estado de presencia de una sesión abierta en vea_login_log
 * (activo / inactivo / por_cerrar). El panel ADM lo usa para mostrar, en vivo,
 * quién está conectado. Nunca bloquea la petición del usuario.
 */
async function marcarPresencia(sid, estado) {
  if (!sid) return;
  const claves = clavesSupabase();
  if (!claves) return;
  const limpio = String(estado || 'activo').slice(0, 20);
  const url = `${SUPABASE_URL}/rest/v1/vea_login_log?sesion_id=eq.${encodeURIComponent(sid)}&salida=is.null`;
  const cab = { ...claves, 'Content-Type': 'application/json', Prefer: 'return=minimal' };
  try {
    const r = await fetch(url, {
      method: 'PATCH',
      headers: cab,
      body: JSON.stringify({ ultimo_visto: new Date().toISOString(), estado: limpio }),
      cache: 'no-store'
    });
    if (r.ok) return;
    // Si la columna «estado» aún no existe, al menos se actualiza la actividad.
    await fetch(url, {
      method: 'PATCH',
      headers: cab,
      body: JSON.stringify({ ultimo_visto: new Date().toISOString() }),
      cache: 'no-store'
    });
  } catch (_) { /* la presencia nunca bloquea */ }
}

/** Cierra la sesión en vea_login_log al hacer logout (guarda la salida). */
async function marcarSalida(sid) {
  if (!sid) return;
  const claves = clavesSupabase();
  if (!claves) return;
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/vea_login_log?sesion_id=eq.${encodeURIComponent(sid)}&salida=is.null`, {
      method: 'PATCH',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ salida: new Date().toISOString(), estado: 'salio' }),
      cache: 'no-store'
    });
  } catch (_) { /* el cierre nunca bloquea */ }
}

/** Cierra todas las sesiones abiertas de un correo (p. ej. al desactivar la cuenta). */
async function marcarSalidaPorEmail(email) {
  const correo = String(email || '').trim().toLowerCase();
  if (!correo) return;
  const claves = clavesSupabase();
  if (!claves) return;
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/vea_login_log?email=eq.${encodeURIComponent(correo)}&salida=is.null`, {
      method: 'PATCH',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ salida: new Date().toISOString(), estado: 'salio' }),
      cache: 'no-store'
    });
  } catch (_) { /* nunca bloquea */ }
}

const MINUTOS_BLOQUEO = 15;
const FALLOS_ADM = 5;
const FALLOS_USUARIO = 10;

// Solo cuentas Google de este dominio entran al módulo (punto 2 auditoría).
// Se puede cambiar sin código con la variable VEA_GOOGLE_DOMINIO en Vercel.
const DOMINIO_GOOGLE = String(process.env.VEA_GOOGLE_DOMINIO || 'hospitaldeventanilla.gob.pe').toLowerCase();

function correoGooglePermitido(email) {
  const partes = String(email || '').toLowerCase().split('@');
  return partes.length === 2 && partes[0].length > 0 && partes[1] === DOMINIO_GOOGLE;
}

function minutosRestantes(hastaMs) {
  return Math.max(1, Math.ceil((hastaMs - Date.now()) / 60000));
}

/**
 * Permisos por módulo — «cada usuario ve solo lo que le compete».
 * Se guardan en public.vea_config (tabla que el sistema ya crea solo) bajo la
 * clave MODULOS_VEA_CONFIG con la forma { "correo": ["soat","vih"] }.
 * Sin asignación previa = sin acceso (mínimo privilegio). El ADM siempre ve todo.
 */
const MODULOS_VEA = ['vigilancia', 'individual', 'soat', 'vih', 'tbc', 'iass'];
const CLAVE_MODULOS = 'modulos_usuarios';
// Módulo -> tablas de /api/vea-data que habilita (iass no se sirve por API).
const TABLAS_POR_MODULO = {
  vigilancia: ['edas', 'iras', 'febriles'],
  individual: ['individual'],
  soat: ['soat'],
  vih: ['vih'],
  tbc: ['tbc'],
  iass: []
};

function limpiarModulos(lista) {
  if (!Array.isArray(lista)) return [];
  const vistos = new Set();
  return MODULOS_VEA.filter(m => lista.indexOf(m) >= 0 && !vistos.has(m) && vistos.add(m));
}

async function leerPermisosModulos() {
  const lectura = await leerConfig([CLAVE_MODULOS]);
  if (!lectura || lectura.error || !lectura.cfg) return {};
  const crudo = lectura.cfg[CLAVE_MODULOS];
  if (!crudo) return {};
  let obj = null;
  try { obj = JSON.parse(crudo); } catch (_) { return {}; }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return {};
  const salida = {};
  Object.keys(obj).forEach(function (correo) {
    if (!correo) return;
    salida[String(correo).trim().toLowerCase()] = limpiarModulos(obj[correo]);
  });
  return salida;
}

async function guardarPermisosModulos(mapa) {
  const limpio = {};
  Object.keys(mapa || {}).forEach(function (correo) {
    const c = String(correo).trim().toLowerCase();
    const lista = limpiarModulos(mapa[correo]);
    if (!c) return;
    if (lista.length) limpio[c] = lista;
  });
  return guardarConfig({ [CLAVE_MODULOS]: JSON.stringify(limpio) });
}

/** Módulos asignados a un correo (ADM = todos). */
async function modulosDeCorreo(correo) {
  const c = String(correo || '').trim().toLowerCase();
  if (!c) return [];
  const mapa = await leerPermisosModulos();
  return limpiarModulos(mapa[c] || []);
}

/** ¿La petición viene de una sesión de administrador? (cookie ADM o correo ADM) */
async function esAdminSesion(req, datosSesion) {
  try {
    if (sesionAdm(req) && await admActivo(req)) return true;
    const email = String((datosSesion && datosSesion.email) || '').toLowerCase();
    if (!email) return false;
    const lectura = await leerConfig(['adm_email']);
    const cfg = (lectura && lectura.cfg) || {};
    return Boolean(cfg.adm_email) && email === String(cfg.adm_email).toLowerCase();
  } catch (_) { return false; }
}

module.exports = {
  clavesSupabase,
  errorTabla,
  leerConfig,
  guardarConfig,
  admActivo,
  sesionActiva,
  CLAVE_EPOCH_SESION,
  leerEpochSesion,
  textoSeguro,
  tokenSesion,
  marcarVisto,
  marcarPresencia,
  marcarSalida,
  marcarSalidaPorEmail,
  MINUTOS_BLOQUEO,
  FALLOS_ADM,
  FALLOS_USUARIO,
  DOMINIO_GOOGLE,
  correoGooglePermitido,
  minutosRestantes,
  MODULOS_VEA,
  CLAVE_MODULOS,
  TABLAS_POR_MODULO,
  limpiarModulos,
  leerPermisosModulos,
  guardarPermisosModulos,
  modulosDeCorreo,
  esAdminSesion
};
