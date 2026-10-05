/**
 * VEA — Registro de accesos (solo ADM).
 * GET /api/auth/log → { accesos: [...] } últimas 200 filas de vea_login_log.
 * Requiere cookie vea_adm válida (usuario + contraseña de administración).
 */
const { admActivo } = require('../../lib/control');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  res.setHeader('Cache-Control', 'no-store, max-age=0');

  if (!(await admActivo(req))) {
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
    // Purga perezosa: al cargar el registro se borran filas de más de 12 meses.
    // Mantiene la tabla acotada sin necesidad de cron ni jobs externos.
    const corte = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString();
    await fetch(
      `${SUPABASE_URL}/rest/v1/vea_login_log?creado_en=lt.${encodeURIComponent(corte)}`,
      { method: 'DELETE', headers: { apikey: service, Authorization: `Bearer ${service}`, Prefer: 'return=minimal' }, cache: 'no-store' }
    );

    const r = await fetch(
      `${SUPABASE_URL}/rest/v1/vea_login_log?select=creado_en,email,nombre,proveedor,ip,exito,user_agent,sesion_id,salida,ultimo_visto&order=creado_en.desc&limit=200`,
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
