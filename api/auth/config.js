/**
 * VEA — Estado de la configuración de acceso.
 * GET /api/auth/config → { google: bool, adm: bool, secret: bool }
 * Lo usa login.html para mostrar u ocultar el botón "Continuar con Google".
 */
module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  return res.status(200).json({
    google: Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
    adm: Boolean(process.env.VEA_ADM_USER && process.env.VEA_ADM_PASS),
    secret: Boolean(process.env.VEA_AUTH_SECRET)
  });
};
