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

async function admActivo(req) {
  const datos = sesionAdm(req);
  if (!datos) return null;
  const lectura = await leerConfig(['adm_ses']);
  // Falla cerrada: si la configuración no es legible NO se acepta la sesión
  // (antes se degradaba y se aceptaba, saltándose la invalidación por clave).
  if (lectura.error || !lectura.cfg) return null;
  const version = lectura.cfg.adm_ses;
  if (version && String(datos.v || '') !== version) return null; // sesión de antes del cambio de clave
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

/** Cierra la sesión en vea_login_log al hacer logout (guarda la salida). */
async function marcarSalida(sid) {
  if (!sid) return;
  const claves = clavesSupabase();
  if (!claves) return;
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/vea_login_log?sesion_id=eq.${encodeURIComponent(sid)}&salida=is.null`, {
      method: 'PATCH',
      headers: { ...claves, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ salida: new Date().toISOString() }),
      cache: 'no-store'
    });
  } catch (_) { /* el cierre nunca bloquea */ }
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

module.exports = {
  clavesSupabase,
  errorTabla,
  leerConfig,
  guardarConfig,
  admActivo,
  sesionActiva,
  textoSeguro,
  tokenSesion,
  marcarVisto,
  marcarSalida,
  MINUTOS_BLOQUEO,
  FALLOS_ADM,
  FALLOS_USUARIO,
  DOMINIO_GOOGLE,
  correoGooglePermitido,
  minutosRestantes
};
