/**
 * VEA — Estado de la sesión actual.
 * GET /api/auth/me → { autenticado, email, nombre, adm }
 */
const { sesionAdm } = require('../../lib/session');
const { admActivo, marcarVisto, leerConfig, sesionActiva, clavesSupabase,
        esAdminSesion, modulosDeCorreo, MODULOS_VEA } = require('../../lib/control');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  res.setHeader('Cache-Control', 'no-store, max-age=0');
  // Misma regla que /api/vea-data, /api/alerts y /api/app: cookie vigente +
  // dominio Google permitido + cuenta activa + sesion_v sin cambiar.
  const activa = await sesionActiva(req);
  if (!activa.ok) {
    return res.status(401).json({ autenticado: false, adm: false });
  }
  const datos = activa.datos;
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
  // Permiso de «Importación de Datos»: siempre el ADM, o la cuenta de
  // vea_usuarios con puede_importar=true habilitada desde el panel ADM.
  // Fail-closed: si la columna/tabla no existe o falla la lectura → false.
  let puedeImportar = adm || admEmail;
  if (!puedeImportar && datos.email) {
    try {
      const claves = clavesSupabase();
      if (claves) {
        const rq = await fetch(
          `${SUPABASE_URL}/rest/v1/vea_usuarios?usuario=eq.${encodeURIComponent(String(datos.email).toLowerCase())}&select=puede_importar,activo&limit=1`,
          { headers: claves, cache: 'no-store' }
        );
        const fr = rq.ok ? await rq.json().catch(() => null) : null;
        const fu = Array.isArray(fr) && fr.length ? fr[0] : null;
        puedeImportar = Boolean(fu && fu.activo !== false && fu.puede_importar === true);
      }
    } catch (_) { puedeImportar = false; }
  }
  // Permisos por módulo: el ADM recibe la lista completa; el resto, la suya.
  // Fail-closed: si no se puede leer, se responde lista vacía (nada de módulos).
  const esAdmin = adm || admEmail || await esAdminSesion(req, datos);
  let modulos = [];
  if (esAdmin) {
    modulos = MODULOS_VEA.slice();
  } else if (datos.email) {
    try { modulos = await modulosDeCorreo(datos.email); } catch (_) { modulos = []; }
  }
  return res.status(200).json({
    autenticado: true,
    email: datos.email || '',
    nombre: datos.nombre || '',
    proveedor: datos.proveedor || '',
    debe_cambiar: Boolean(datos.dc),
    admEmail: admEmail,
    adm: adm,
    es_admin: esAdmin,
    modulos: modulos,
    puede_importar: puedeImportar
  });
};
