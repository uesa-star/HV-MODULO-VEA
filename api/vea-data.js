/**
 * VEA — Datos de vigilancia + alertas (función única: el plan Hobby solo
 * permite 12 funciones serverless por deployment).
 *   GET /api/vea-data?table=...          → registros de una tabla permitida.
 *   GET /api/vea-data?ruta=alerts        → { alertas:[], actualizadoEn, fuente }
 *        (antes era /api/alerts: el cliente lo pide con ruta=alerts y el
 *        rewrite de vercel.json conserva la URL vieja para HTML cacheado).
 */
module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const { sesionActiva } = require('../lib/control');
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  const sesionOk = await sesionActiva(req);
  if (!sesionOk.ok) {
    return res.status(sesionOk.status || 401).json({ error: sesionOk.error || 'No autenticado' });
  }

  /* ---------- alertas del carrusel (antes /api/alerts) ---------- */
  if (String(req.query.ruta || '') === 'alerts') {
    // El cliente combina esto con su catálogo local (VEA_ALERTAS_OFICIALES_F474)
    // y elimina duplicados por url. Responde 200 con timestamp real (no 404).
    return res.status(200).json({
      alertas: [],
      actualizadoEn: new Date().toISOString(),
      fuente: 'catalogo-local-vea'
    });
  }

  const allowed = new Set(['edas', 'iras', 'febriles', 'individual']);
  const table = String(req.query.table || '').toLowerCase();
  if (!allowed.has(table)) return res.status(400).json({ error: 'Tabla no permitida' });

  const rawOffset = Number.parseInt(String(req.query.offset || '0'), 10);
  const rawLimit = Number.parseInt(String(req.query.limit || '300'), 10);
  const offset = Number.isFinite(rawOffset) && rawOffset >= 0 ? rawOffset : 0;
  const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(rawLimit, 500)) : 300;
  const rawYear = String(req.query.year || '').trim();
  const year = /^\d{4}$/.test(rawYear) ? rawYear : null;

  // Llave del SERVIDOR (service_role): los datos se sirven solo con sesión
  // válida. La llave pública del navegador ya no se usa ni se acepta, porque
  // la tabla `individual` (datos de pacientes) no tiene acceso anónimo.
  const k = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
  if (!k) return res.status(503).json({ error: 'Base de datos no configurada.' });

  const params = new URLSearchParams({ select: '*', offset: String(offset), limit: String(limit) });
  // No usar _row_id: puede no existir en la tabla y dejar todos los gráficos sin datos.
  // El orden epidemiológico se resuelve en el cliente después de recibir los registros.

  // El cliente (móvil) envía year=YYYY esperando filtrado en servidor. El filtro se
  // aplica con el nombre canónico snake_case "ano" que usa sync_vea.py en todas
  // las tablas (edas/iras/febriles/individual).
  if (year) params.append('ano', `eq.${year}`);

  const upstreamUrl = `https://qtsfkoasfoaovadilwgk.supabase.co/rest/v1/${encodeURIComponent(table)}?${params.toString()}`;
  try {
    const upstream = await fetch(upstreamUrl, {
      method: 'GET',
      headers: { apikey: k, Authorization: `Bearer ${k}`, Accept: 'application/json' },
      cache: 'no-store'
    });
    const body = await upstream.text();
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.setHeader('Content-Type', upstream.headers.get('content-type') || 'application/json; charset=utf-8');
    return res.status(upstream.status).send(body);
  } catch (err) {
    console.error('[vea-data] error:', String(err?.message || err));
    return res.status(502).json({ error: 'No se pudo consultar la base de datos' });
  }
};
