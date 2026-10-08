/**
 * VEA — Publicación/Envío del boletín epidemiológico (SOLO ADM).
 * GET  /api/vea-boletin          → { correo }  configuración vigente
 * POST /api/vea-boletin          → acciones:
 *   { accion:'guardar_correo', correo:'a@b.c, d@e.f' }
 *        Guarda (editable en todo momento) el correo del responsable de la web.
 *   { accion:'publicar', anio, se, titulo, resumen, html, pdf_b64,
 *     publicar:true, enviar:true }
 *        · publicar → sube/actualiza el boletín en el listado público (vea_boletines)
 *        · enviar   → correo formal al editor de gob.pe con el PDF adjunto (si existe)
 * Seguridad: sesión ADM fail-closed (401), validación de todos los campos,
 * límites de tamaño, texto seguro y auditoría en la propia fila del boletín.
 */
const { admActivo, leerConfig, guardarConfig, textoSeguro } = require('../lib/control');
const { enviarCorreo } = require('../lib/correo');
const { asegurarTablas } = require('../lib/tablas');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';
const BASE_URL = String(process.env.VEA_BASE_URL || 'https://vigilancia-epidemiologica-ecru.vercel.app').replace(/\/+$/, '');
const CLAVE_CORREO = 'boletin_correo';
const CLAVE_CORREO_CAMBIO = 'boletin_correo_cambio';
const MAX_HTML = 1600000;      // ~1.6 MB (el boletín V17 pesa ~250 KB)
const MAX_PDF_B64 = 3400000;   // ~2.5 MB binarios: deja holgura bajo el límite de 4.5 MB de Vercel
const RE_CORREO = /^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]{2,}$/;

function parseCorreos(valor) {
  const v = String(valor || '').trim();
  if (!v) return [];
  return [...new Set(v.split(/[,;\s]+/).map(function (s) { return s.trim(); }).filter(Boolean))];
}

function claves() {
  const k = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
  return k ? { apikey: k, Authorization: `Bearer ${k}`, 'Content-Type': 'application/json' } : null;
}

async function leerIdExistente(k, anio, se) {
  const r = await fetch(`${SUPABASE_URL}/rest/v1/vea_boletines?anio=eq.${anio}&se=eq.${se}&select=id`, {
    headers: k, cache: 'no-store'
  });
  if (!r.ok) return { error: r.status };
  const filas = await r.json().catch(() => []);
  return { id: Array.isArray(filas) && filas.length ? Number(filas[0].id) : null };
}

async function guardarBoletin(datos, reintento) {
  const k = claves();
  if (!k) return { error: 'Sin credenciales de base de datos en Vercel.' };
  try {
    const existente = await leerIdExistente(k, datos.anio, datos.se);
    if (existente.error && (existente.error === 404 || existente.error === 400) && !reintento) {
      if (await asegurarTablas()) return guardarBoletin(datos, true);
      return { error: 'La tabla vea_boletines no existe y no se pudo crear.' };
    }
    if (existente.error) return { error: 'No se pudo consultar el listado de boletines.' };
    if (existente.id) {
      const r = await fetch(`${SUPABASE_URL}/rest/v1/vea_boletines?id=eq.${existente.id}`, {
        method: 'PATCH',
        headers: { ...k, Prefer: 'return=representation' },
        body: JSON.stringify(datos),
        cache: 'no-store'
      });
      const filas = r.ok ? await r.json().catch(() => []) : [];
      if (!r.ok) return { error: 'No se pudo actualizar el boletín.' };
      return { id: Number((Array.isArray(filas) && filas[0] && filas[0].id) || existente.id) };
    }
    const r = await fetch(`${SUPABASE_URL}/rest/v1/vea_boletines`, {
      method: 'POST',
      headers: { ...k, Prefer: 'return=representation' },
      body: JSON.stringify(datos),
      cache: 'no-store'
    });
    if (r.status === 409) return guardarBoletin(datos, true); // carrera por índice único
    const filas = r.ok ? await r.json().catch(() => []) : [];
    if (!r.ok) return { error: 'No se pudo publicar el boletín.' };
    return { id: Number((Array.isArray(filas) && filas[0] && filas[0].id) || 0) || null };
  } catch (_) {
    return { error: 'No se pudo contactar con la base de datos.' };
  }
}

async function marcarEnvio(id, campos) {
  const k = claves();
  if (!k) return;
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/vea_boletines?id=eq.${id}`, {
      method: 'PATCH',
      headers: { ...k, Prefer: 'return=minimal' },
      body: JSON.stringify(campos),
      cache: 'no-store'
    });
  } catch (_) { /* la auditoría nunca bloquea la operación */ }
}

function plantillaCorreo({ titulo, resumen, anio, se, enlace, conAdjunto, remitente }) {
  const fecha = new Date().toLocaleDateString('es-PE', { day: '2-digit', month: 'long', year: 'numeric' });
  return `<!doctype html><html><body style="margin:0;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;color:#1e293b">
  <div style="max-width:620px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0">
    <div style="background:#0056ac;padding:18px 24px">
      <div style="color:#ffffff;font-size:13px;letter-spacing:1px">HOSPITAL DE VENTANILLA · UNIDAD DE EPIDEMIOLOGÍA Y SALUD PÚBLICA</div>
      <div style="color:#ffffff;font-size:19px;font-weight:bold;margin-top:4px">Boletín epidemiológico — S.E. ${String(se).padStart(2, '0')} · ${anio}</div>
    </div>
    <div style="padding:22px 24px">
      <p style="font-size:15px;font-weight:bold;margin:0 0 8px">${titulo}</p>
      <p style="font-size:14px;line-height:1.6;color:#334155;margin:0 0 18px">${resumen}</p>
      <p style="margin:0 0 6px"><a href="${enlace}" style="display:inline-block;background:#0056ac;color:#ffffff;text-decoration:none;font-weight:bold;padding:11px 20px;border-radius:6px">Ver boletín en línea</a></p>
      <p style="font-size:13px;color:#64748b;margin:18px 0 0">${conAdjunto ? 'Adjunto encontrará el boletín en PDF para su publicación en' : 'El boletín queda disponible en'} gob.pe/hdv → «Informes, publicaciones e informes».</p>
      <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0">
      <p style="font-size:12px;color:#94a3b8;margin:0">Generado por el Módulo VEA (${remitente || 'Unidad de Epidemiología'}) el ${fecha}, tras la validación epidemiológica de la semana.</p>
    </div>
  </div>
</body></html>`;
}

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');

  if (req.method !== 'GET' && req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  // Sesión ADM obligatoria — falla cerrada (mismo criterio que /api/auth/log).
  const adm = await admActivo(req);
  if (!adm) return res.status(401).json({ error: 'Se requiere sesión de administrador' });

  if (req.method === 'GET') {
    const lectura = await leerConfig([CLAVE_CORREO, CLAVE_CORREO_CAMBIO]);
    if (lectura.error && !lectura.cfg) return res.status(502).json({ error: lectura.error });
    return res.status(200).json({
      correo: (lectura.cfg && lectura.cfg[CLAVE_CORREO]) || '',
      correoCambio: (lectura.cfg && lectura.cfg[CLAVE_CORREO_CAMBIO]) || ''
    });
  }

  let body;
  try {
    body = JSON.parse(typeof req.body === 'string' ? req.body : (req.body ? JSON.stringify(req.body) : '{}'));
  } catch (_) {
    return res.status(400).json({ error: 'Cuerpo inválido.' });
  }
  const accion = String(body.accion || '');

  /* ---------- guardar el correo del responsable de la web (editable) ---------- */
  if (accion === 'guardar_correo') {
    const correos = parseCorreos(body.correo);
    if (correos.length > 5) return res.status(400).json({ error: 'Máximo 5 correos destino.' });
    for (const c of correos) {
      if (c.length > 120 || !RE_CORREO.test(c)) {
        return res.status(400).json({ error: 'Correo inválido: ' + textoSeguro(c, 60) });
      }
    }
    const guardado = await guardarConfig({
      [CLAVE_CORREO]: correos.join(', '),
      [CLAVE_CORREO_CAMBIO]: `${textoSeguro(adm.email || '', 80)} · ${new Date().toISOString()}`
    });
    if (!guardado) return res.status(502).json({ error: 'No se pudo guardar la configuración.' });
    return res.status(200).json({ ok: true, correo: correos.join(', ') });
  }

  /* ---------- publicar y/o enviar el boletín ---------- */
  if (accion === 'publicar') {
    const anio = Number(body.anio);
    const se = Number(body.se);
    if (!Number.isInteger(anio) || anio < 2024 || anio > 2100) return res.status(400).json({ error: 'Año inválido.' });
    if (!Number.isInteger(se) || se < 1 || se > 53) return res.status(400).json({ error: 'Semana epidemiológica inválida.' });

    const titulo = textoSeguro(body.titulo, 200);
    const resumen = textoSeguro(body.resumen, 600);
    const html = typeof body.html === 'string' ? body.html : '';
    if (!html || html.length > MAX_HTML) return res.status(400).json({ error: 'Documento del boletín inválido o demasiado grande.' });
    if (!/<(html|!doctype)/i.test(html)) return res.status(400).json({ error: 'Documento del boletín inválido.' });

    let pdf = typeof body.pdf_b64 === 'string' ? body.pdf_b64.replace(/\s+/g, '') : '';
    if (pdf) {
      if (pdf.length > MAX_PDF_B64 || !/^[A-Za-z0-9+/]+={0,2}$/.test(pdf)) {
        return res.status(400).json({ error: 'PDF inválido o demasiado grande (máx. 2.5 MB).' });
      }
    }
    // Límite de Vercel: 4.5 MB por petición — html + pdf en conjunto deben caber.
    if (html.length + pdf.length > 4300000) {
      return res.status(400).json({ error: 'Documento + PDF superan el tamaño permitido: publique sin PDF (irá con enlace).' });
    }

    const publicar = body.publicar !== false;
    const enviar = body.enviar === true;

    // El envío exige el correo configurado (editable en este mismo panel).
    let destinos = [];
    if (enviar) {
      const lectura = await leerConfig([CLAVE_CORREO]);
      if (lectura.error && !lectura.cfg) return res.status(502).json({ error: lectura.error });
      destinos = parseCorreos((lectura.cfg || {})[CLAVE_CORREO]);
      if (!destinos.length) {
        return res.status(400).json({ error: 'Sin correo configurado: guardé el correo del responsable de la web antes de enviar.' });
      }
    }

    if (!publicar && !enviar) return res.status(400).json({ error: 'Nada que hacer: marque publicar y/o enviar.' });

    let id = null;
    if (publicar) {
      const datos = {
        anio, se, titulo, resumen, html, pdf_base64: pdf, tiene_pdf: !!pdf,
        creado_por: textoSeguro(adm.email || '', 120),
        creado_en: new Date().toISOString()
      };
      const r = await guardarBoletin(datos);
      if (r.error) return res.status(502).json({ error: r.error });
      id = r.id;
    } else {
      const k = claves();
      if (k) {
        const existente = await leerIdExistente(k, anio, se);
        id = existente.id;
      }
      if (!id) return res.status(400).json({ error: 'Primero publique el boletín (no existe en el listado).' });
    }

    const enlace = `${BASE_URL}/boletines/${id}`;
    const respuesta = { ok: true, id, enlace, enviado: false, adjunto: !!pdf };

    if (enviar) {
      const asunto = `BOLETÍN EPIDEMIOLÓGICO SE-${String(se).padStart(2, '0')}-${anio} · Hospital de Ventanilla`;
      const correoHtml = plantillaCorreo({
        titulo: titulo || `Boletín epidemiológico — S.E. ${String(se).padStart(2, '0')} · ${anio}`,
        resumen: resumen || `Boletín epidemiológico de la S.E. ${String(se).padStart(2, '0')} · ${anio} del Hospital de Ventanilla.`,
        anio, se, enlace, conAdjunto: !!pdf, remitente: adm.email || ''
      });
      const adjuntos = pdf ? [{
        nombre: `Boletin_Epidemiologico_SE${String(se).padStart(2, '0')}_${anio}.pdf`,
        base64: pdf,
        tipo: 'application/pdf'
      }] : [];
      const enviados = [];
      const fallos = [];
      for (const destino of destinos) {
        const r = await enviarCorreo({ para: destino, asunto, html: correoHtml, adjuntos });
        if (r.ok) enviados.push(destino);
        else fallos.push({ correo: destino, error: textoSeguro(String(r.error || r.detalle || 'error'), 80) });
      }
      respuesta.enviado = enviados.length > 0;
      respuesta.destinos = enviados;
      respuesta.fallos = fallos;
      respuesta.adjunto = respuesta.adjunto && enviados.length > 0;
      await marcarEnvio(id, {
        correo_destino: textoSeguro(destinos.join(', '), 300),
        enviado: enviados.length > 0,
        enviado_detalle: textoSeguro(
          enviados.length
            ? `enviado a ${enviados.join(', ')}${fallos.length ? ` · falló: ${fallos.map(f => f.correo).join(', ')}` : ''}`
            : `falló en ${fallos.map(f => f.correo).join(', ')}`,
          500
        )
      });
      if (!enviados.length) {
        return res.status(502).json({
          ok: false, publicado: true, id, enlace, enviado: false, adjunto: false,
          error: 'Boletín publicado pero el correo no pudo enviarse: ' + (fallos[0] ? fallos[0].error : 'sin detalle') +
            '. Verifique la configuración de correo en Vercel.'
        });
      }
    }

    return res.status(200).json(respuesta);
  }

  return res.status(400).json({ error: 'Acción no reconocida.' });
};
