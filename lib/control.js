/**
 * VEA — Control de administración compartido:
 *  · lectura/escritura de public.vea_config (auto-creable vía lib/tablas)
 *  · admActivo(req): sesión ADM válida (cookie + versión de sesión — se invalida
 *    al cambiar la contraseña, C)
 *  · contadores de intentos fallidos (bloqueo anti fuerza bruta — B)
 */
const crypto = require('crypto');
const { sesionAdm } = require('./session');
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
  if (lectura.error || !lectura.cfg) return datos; // sin config legible: degradar y aceptar
  const version = lectura.cfg.adm_ses;
  if (version && String(datos.v || '') !== version) return null; // sesión de antes del cambio de clave
  return datos;
}

function tokenSesion() {
  return crypto.randomBytes(16).toString('hex');
}

const MINUTOS_BLOQUEO = 15;
const FALLOS_ADM = 5;
const FALLOS_USUARIO = 10;

function minutosRestantes(hastaMs) {
  return Math.max(1, Math.ceil((hastaMs - Date.now()) / 60000));
}

module.exports = {
  clavesSupabase,
  errorTabla,
  leerConfig,
  guardarConfig,
  admActivo,
  tokenSesion,
  MINUTOS_BLOQUEO,
  FALLOS_ADM,
  FALLOS_USUARIO,
  minutosRestantes
};
