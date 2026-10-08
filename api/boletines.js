/**
 * VEA — Listado público de boletines epidemiológicos (sin sesión).
 * GET /api/boletines            → { boletines:[{id,anio,se,titulo,resumen,creado_en,tiene_pdf}] }
 * GET /api/boletines?i=<id>     → documento HTML del boletín (con CSP sandbox:
 *                                  scripts propios del boletín corren, pero en
 *                                  origen opaco — no tocan cookies ni API).
 * GET /api/boletines?i=<id>&pdf=1 → PDF descargable (si se adjuntó al publicar).
 * Solo devuelve lo que el ADM publicó explícitamente en vea_boletines.
 */
const { clavesSupabase, errorTabla } = require('../lib/control');
const { asegurarTablas } = require('../lib/tablas');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';

async function consultar(query, reintento) {
  const k = clavesSupabase();
  if (!k) return { error: 503 };
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/${query}`, { headers: k, cache: 'no-store' });
    if (!r.ok) {
      const texto = await r.text().catch(() => '');
      if (!reintento && errorTabla(texto)) {
        if (await asegurarTablas()) return consultar(query, true);
      }
      console.error('[boletines] Supabase', r.status, texto.slice(0, 200));
      return { error: r.status };
    }
    const datos = await r.json().catch(() => []);
    return { datos };
  } catch (_) {
    return { error: 0 };
  }
}

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const i = String(req.query && req.query.i != null ? req.query.i : '');
  const conPdf = String(req.query && req.query.pdf != null ? req.query.pdf : '') === '1';

  /* ---------- documento de un boletín ---------- */
  if (i !== '') {
    if (!/^\d{1,12}$/.test(i)) return res.status(400).json({ error: 'Identificador inválido.' });
    const consulta = conPdf
      ? `vea_boletines?select=pdf_base64&id=eq.${i}&limit=1`
      : `vea_boletines?select=html,anio,se,titulo&id=eq.${i}&limit=1`;
    const r = await consultar(consulta);
    if (r.error === 404 || r.error === 400) return res.status(404).json({ error: 'Boletín no encontrado.' });
    if (r.error || !Array.isArray(r.datos) || !r.datos.length) {
      return res.status(r.error && r.error !== 0 ? 502 : 404).json({ error: 'Boletín no disponible.' });
    }
    const fila = r.datos[0];

    if (conPdf) {
      const b64 = String(fila.pdf_base64 || '').replace(/\s+/g, '');
      if (!b64) return res.status(404).json({ error: 'Este boletín no tiene PDF descargable.' });
      let buffer;
      try { buffer = Buffer.from(b64, 'base64'); } catch (_) { return res.status(500).json({ error: 'PDF ilegible.' }); }
      const nombre = `Boletin_Epidemiologico_SE${String(Number(fila.se)).padStart(2, '0')}_${Number(fila.anio)}.pdf`;
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `inline; filename="${nombre}"`);
      res.setHeader('Cache-Control', 'public, max-age=600');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      return res.status(200).send(buffer);
    }

    const html = String(fila.html || '');
    if (!html) return res.status(404).json({ error: 'Boletín vacío.' });
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    // Origen opaco: el documento conserva sus botones (imprimir/zoom) pero no
    // puede leer cookies, llamar a la API del módulo ni redirigir a otros orígenes.
    res.setHeader('Content-Security-Policy', 'sandbox allow-scripts');
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Robots-Tag', 'noindex');
    return res.status(200).send(html);
  }

  /* ---------- listado ---------- */
  const r = await consultar('vea_boletines?select=id,anio,se,titulo,resumen,creado_en,tiene_pdf&order=anio.desc,se.desc&limit=60');
  if (r.error) {
    return res.status(r.error === 503 ? 503 : 502).json({ error: 'Listado no disponible.' });
  }
  const boletines = (Array.isArray(r.datos) ? r.datos : []).map(function (f) {
    return {
      id: Number(f.id),
      anio: Number(f.anio),
      se: Number(f.se),
      titulo: String(f.titulo || '').slice(0, 200),
      resumen: String(f.resumen || '').slice(0, 600),
      creado_en: f.creado_en || '',
      tiene_pdf: Boolean(f.tiene_pdf)
    };
  });
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=120');
  return res.status(200).send(JSON.stringify({ boletines }));
};
