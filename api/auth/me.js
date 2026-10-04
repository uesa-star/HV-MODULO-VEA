/**
 * VEA — Estado de la sesión actual.
 * GET /api/auth/me → { autenticado, email, nombre, adm }
 */
const { sesion, sesionAdm } = require('../../lib/session');
const { admActivo } = require('../../lib/control');

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
  if (sesionAdm(req)) adm = Boolean(await admActivo(req));
  return res.status(200).json({
    autenticado: true,
    email: datos.email || '',
    nombre: datos.nombre || '',
    adm: adm
  });
};
