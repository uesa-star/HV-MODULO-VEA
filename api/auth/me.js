/**
 * VEA — Estado de la sesión actual.
 * GET /api/auth/me → { autenticado, email, nombre, adm }
 */
const { sesion, sesionAdm } = require('../../lib/session');
const { admActivo, marcarVisto } = require('../../lib/control');

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
  let adm = false;
  const vistas = [];
  if (datos.sid) vistas.push(datos.sid);
  if (sesionAdm(req)) {
    const a = await admActivo(req);
    adm = Boolean(a);
    if (a && a.sid && a.sid !== datos.sid) vistas.push(a.sid);
  }
  await Promise.all(vistas.map(marcarVisto));
  return res.status(200).json({
    autenticado: true,
    email: datos.email || '',
    nombre: datos.nombre || '',
    proveedor: datos.proveedor || '',
    debe_cambiar: Boolean(datos.dc),
    adm: adm
  });
};
