/**
 * VEA — Endpoint de alertas oficiales para el carrusel del módulo.
 * GET /api/alerts → { alertas: [...], actualizadoEn: ISO8601 }
 *
 * El cliente (veaActualizarAlertasAutomaticasF486) combina estas alertas
 * con su catálogo de respaldo local y elimina duplicados por url.
 * Hoy el catálogo remoto está vacío: las alertas vigentes 2026 viven en
 * index.html (VEA_ALERTAS_OFICIALES_F474). Este endpoint existe para que
 * la consulta automática reciba 200 con timestamp real en lugar de 404.
 */
module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  res.setHeader('Cache-Control', 'no-store, max-age=0');
  return res.status(200).json({
    alertas: [],
    actualizadoEn: new Date().toISOString(),
    fuente: 'catalogo-local-vea'
  });
};
