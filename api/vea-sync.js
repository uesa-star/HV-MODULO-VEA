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

  // ESCRITURA RESTRINGIDA: sin sesión ADM este endpoint permitía cargar miles
  // de registros (incluida la tabla `individual`) con la llave del servidor.
  const { admActivo } = require('../lib/control');
  let adm = null;
  try {
    adm = await admActivo(req);
  } catch (_) {
    adm = null;
  }
  if (!adm) {
    return res.status(401).json({ ok: false, error: 'Requiere sesión de administrador.' });
  }

  const supabaseUrl = String(process.env.SUPABASE_URL || '').replace(/\/+$/, '');
  const serviceRoleKey = String(process.env.SUPABASE_SERVICE_ROLE_KEY || '');

  if (!supabaseUrl || !serviceRoleKey) {
    return res.status(503).json({
      ok: false,
      error: 'Configuración de servidor incompleta'
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
  // Solo columnas con nombre de columna válido: evita claves raras en el cuerpo
  // que PostgREST interprete como columnas inexistentes o filtros.
  const columnasMalas = registros.some(row =>
    Object.keys(row).some(c => !/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(c))
  );
  if (columnasMalas) {
    return res.status(400).json({ ok: false, error: 'Nombre de columna inválido en el lote' });
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

    if (!upstream.ok) {
      // Nunca se devuelve el cuerpo crudo de Supabase al cliente.
      console.error('[vea-sync] Supabase rechazó la carga:', upstream.status, tabla);
      return res.status(502).json({
        ok: false,
        error: 'La base de datos rechazó la carga. Revise los datos e intente nuevamente.'
      });
    }

    return res.status(200).json({
      ok: true,
      estado: conflictTarget ? 'UPSERT_CONFIRMADO_POR_SUPABASE' : 'INSERT_CONFIRMADO_POR_SUPABASE',
      tabla,
      recibidos: registros.length
    });
  } catch (error) {
    console.error('[vea-sync] error de red:', String(error?.message || error));
    return res.status(502).json({
      ok: false,
      error: 'No se pudo contactar con la base de datos'
    });
  }
};
