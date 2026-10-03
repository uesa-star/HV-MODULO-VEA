/**
 * VEA — Registro de accesos (solo ADM).
 * GET /api/auth/log → { accesos: [...] } últimas 200 filas de vea_login_log.
 * Requiere cookie vea_adm válida (usuario + contraseña de administración).
 */
const { sesionAdm } = require('../../lib/session');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  res.setHeader('Cache-Control', 'no-store, max-age=0');

  if (!sesionAdm(req)) {
    return res.status(401).json({ error: 'Se requiere sesión de administrador' });
  }

  const service = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!service) {
    return res.status(503).json({
      error: 'Consulta no disponible',
      detalle: 'Falta SUPABASE_SERVICE_ROLE_KEY en las variables de Vercel.'
    });
  }

  try {
    const r = await fetch(
      `${SUPABASE_URL}/rest/v1/vea_login_log?select=creado_en,email,nombre,proveedor,ip,exito&order=creado_en.desc&limit=200`,
      { headers: { apikey: service, Authorization: `Bearer ${service}` }, cache: 'no-store' }
    );
    const texto = await r.text();
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    if (!r.ok) return res.status(502).send(texto);
    return res.status(200).send(JSON.stringify({ accesos: JSON.parse(texto) }));
  } catch (err) {
    return res.status(502).json({ error: 'No se pudo leer el registro', detail: String(err?.message || err) });
  }
};
