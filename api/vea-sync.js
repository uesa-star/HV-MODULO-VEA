/**
 * VEA — Endpoint seguro de escritura controlada hacia Supabase.
 * Variables Vercel requeridas:
 *   SUPABASE_URL
 *   SUPABASE_SERVICE_ROLE_KEY
 */
const ALLOWED_TABLES = new Set(['edas', 'iras', 'febriles', 'individual']);
const MAX_ROWS = 5000;

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
  }

  const supabaseUrl = String(process.env.SUPABASE_URL || '').replace(/\/+$/, '');
  const serviceRoleKey = String(process.env.SUPABASE_SERVICE_ROLE_KEY || '');

  if (!supabaseUrl || !serviceRoleKey) {
    return res.status(503).json({
      ok: false,
      error: 'Configuración de servidor incompleta',
      detail: 'Faltan variables seguras en Vercel.'
    });
  }

  const body = req.body || {};
  const tabla = String(body.tabla || '').trim().toLowerCase();
  const registros = body.registros;

  if (!ALLOWED_TABLES.has(tabla)) {
    return res.status(400).json({ ok: false, error: 'Tabla no permitida' });
  }
  if (!Array.isArray(registros) || registros.length < 1 || registros.length > MAX_ROWS) {
    return res.status(400).json({ ok: false, error: 'Lote inválido' });
  }
  if (registros.some(row => !row || typeof row !== 'object' || Array.isArray(row))) {
    return res.status(400).json({ ok: false, error: 'Registro inválido en el lote' });
  }

  const conflictTarget = String(body.conflictTarget || '').trim();
  const params = new URLSearchParams({ select: '*' });

  if (conflictTarget) {
    if (!/^[a-zA-Z_][a-zA-Z0-9_,]*$/.test(conflictTarget)) {
      return res.status(400).json({ ok: false, error: 'conflictTarget inválido' });
    }
    params.set('on_conflict', conflictTarget);
  }

  const url = `${supabaseUrl}/rest/v1/${encodeURIComponent(tabla)}?${params.toString()}`;

  try {
    const upstream = await fetch(url, {
      method: 'POST',
      headers: {
        apikey: serviceRoleKey,
        Authorization: `Bearer ${serviceRoleKey}`,
        'Content-Type': 'application/json',
        Prefer: conflictTarget
          ? 'resolution=merge-duplicates,return=representation'
          : 'return=representation'
      },
      body: JSON.stringify(registros)
    });

    const text = await upstream.text();
    let data;
    try { data = JSON.parse(text); } catch { data = text; }

    if (!upstream.ok) {
      return res.status(upstream.status).json({
        ok: false,
        error: 'Supabase rechazó la carga',
        detail: data
      });
    }

    return res.status(200).json({
      ok: true,
      estado: conflictTarget ? 'UPSERT_CONFIRMADO_POR_SUPABASE' : 'INSERT_CONFIRMADO_POR_SUPABASE',
      tabla,
      recibidos: registros.length,
      respuesta: data
    });
  } catch (error) {
    return res.status(502).json({
      ok: false,
      error: 'No se pudo contactar con Supabase',
      detail: String(error?.message || error)
    });
  }
};
