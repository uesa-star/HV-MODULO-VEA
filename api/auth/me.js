/**
 * VEA — Estado de la sesión actual.
 * GET /api/auth/me → { autenticado, email, nombre, adm }
 */
const { sesion, sesionAdm } = require('../../lib/session');
const { admActivo, marcarVisto, clavesSupabase, leerConfig, correoGooglePermitido } = require('../../lib/control');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  res.setHeader('Cache-Control', 'no-store, max-age=0');
  const datos = sesion(req);
  if (!datos) {
    return res.status(401).json({ autenticado: false, adm: false });
  }
  // Google solo institucional: expulsa sesiones de otros dominios aunque la cookie siga vigente.
  if (datos.proveedor === 'google' && !correoGooglePermitido(datos.email)) {
    return res.status(401).json({ autenticado: false, adm: false });
  }
  // Cuentas de correo/contraseña desactivadas (o eliminadas) pierden acceso
  // aunque su cookie siga vigente: la pantalla «Mi contraseña» no las muestra y el guard las expulsa.
  if (datos.proveedor === 'registro' && datos.email) {
    try {
      const claves = typeof clavesSupabase === 'function' ? clavesSupabase() : null;
      if (claves) {
        const rq = await fetch(
          `${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(String(datos.email).toLowerCase())}&select=activo&limit=1`,
          { headers: claves, cache: 'no-store' }
        );
        if (rq.ok) {
          const fr = await rq.json().catch(() => []);
          const fu = Array.isArray(fr) && fr.length ? fr[0] : null;
          if (!fu || fu.activo === false) {
            return res.status(401).json({ autenticado: false, adm: false });
          }
        }
      }
    } catch (_) { /* sin verificación: continúa con la sesión */ }
  }
  let adm = false;
  const vistas = [];
  if (datos.sid) vistas.push(datos.sid);
  if (sesionAdm(req)) {
    const a = await admActivo(req);
    adm = Boolean(a);
    if (a && a.sid && a.sid !== datos.sid) vistas.push(a.sid);
  }
  await Promise.all(vistas.map(marcarVisto));
  // ¿La sesión Google actual es la del correo registrado como administrador?
  // Solo se devuelve sí/no (nunca el correo), para mostrarle la pestaña ADM
  // únicamente a él sin exponer nada a los demás usuarios.
  let admEmail = false;
  if (datos.proveedor === 'google' && datos.email) {
    try {
      const lectura = await leerConfig(['adm_email']);
      const cfg = (lectura && lectura.cfg) || {};
      admEmail = Boolean(cfg.adm_email) &&
        String(datos.email).toLowerCase() === String(cfg.adm_email).toLowerCase();
    } catch (_) { admEmail = false; }
  }
  return res.status(200).json({
    autenticado: true,
    email: datos.email || '',
    nombre: datos.nombre || '',
    proveedor: datos.proveedor || '',
    debe_cambiar: Boolean(datos.dc),
    admEmail: admEmail,
    adm: adm
  });
};
