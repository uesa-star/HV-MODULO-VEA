/**
 * VEA — Estado de la sesión actual.
 * GET /api/auth/me → { autenticado, email, nombre, adm }
 */
const { sesionAdm } = require('../../lib/session');
const { admActivo, marcarVisto, leerConfig, sesionActiva } = require('../../lib/control');

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
