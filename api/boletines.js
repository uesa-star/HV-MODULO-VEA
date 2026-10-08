/**
 * VEA — Boletines epidemiológicos (lista pública + panel ADM en una sola
 * función, por el límite de 12 funciones serverless del plan Hobby).
 *
 * PÚBLICO (sin sesión):
 *   GET /api/boletines            → { boletines:[{id,anio,se,titulo,resumen,creado_en,tiene_pdf}] }
 *   GET /api/boletines?i=<id>     → documento HTML del boletín (con CSP sandbox:
 *                                    scripts propios del boletín corren, pero en
 *                                    origen opaco — no tocan cookies ni API).
 *   GET /api/boletines?i=<id>&pdf=1 → PDF descargable (si se adjuntó al publicar).
 *
 * CRON (Vercel Cron, Authorization: Bearer CRON_SECRET):
 *   GET /api/boletines?auto=1     → envío automático semanal programado en el
 *                                    panel ADM: circular si el último boletín
 *                                    está publicado, recordatorio si no.
 *
 * ADM (sesión obligatoria, fail-closed 401):
 *   GET  /api/boletines?adm=1     → { correo, correoCc, correoCambio, auto, autoProximo }
 *   POST /api/boletines           → acciones:
 *     { accion:'guardar_correo', correo:'a@b.c', correoCc:'d@e.f' }
 *          Guarda Para (máx. 3) y Cc (máx. 7, 10 en total), editable en todo momento.
 *     { accion:'guardar_auto', activo, dia (0=domingo), hora:'HH:MM', correoCc? }
 *          Programación del envío automático semanal (hora de Perú).
 *     { accion:'enviar_prueba' }
 *          Envía la circular real al último boletín publicado (Para + Cc).
 *     { accion:'publicar', anio, se, titulo, resumen, html, pdf_b64,
 *       publicar:true, enviar:true }
 *          · publicar → sube/actualiza el boletín en el listado público (vea_boletines)
 *          · enviar   → circular aprobada a Para + Cc; PDF ≤ 700 KB adjunto,
 *                       si pesa más va botón «Descargar PDF» (Gmail oculta el
 *                       cuerpo cuando el adjunto es muy pesado)
 *
 * Solo el ADM publicó explícitamente: el listado nunca expone HTML/PDF/correos.
 */
const { admActivo, clavesSupabase, errorTabla, leerConfig, guardarConfig, textoSeguro } = require('../lib/control');
const { enviarCorreo } = require('../lib/correo');
const { asegurarTablas } = require('../lib/tablas');
const {
  LIMITE_ADJUNTO_BYTES, asuntoCircular, nombreArchivo,
  listoParaDisparar, proximoEnvioTexto, plantillaCircular, plantillaRecordatorio
} = require('../lib/circular');

const SUPABASE_URL = 'https://qtsfkoasfoaovadilwgk.supabase.co';
const BASE_URL = String(process.env.VEA_BASE_URL || 'https://vigilancia-epidemiologica-ecru.vercel.app').replace(/\/+$/, '');
const CLAVE_CORREO = 'boletin_correo';           // Para (destinos principales)
const CLAVE_CORREO_CC = 'boletin_correo_cc';     // Cc (copias)
const CLAVE_CORREO_CAMBIO = 'boletin_correo_cambio';
const CLAVE_AUTO = 'boletin_auto';               // JSON {activo,dia,hora,ultimo}
const CLAVE_ENVIO_N = 'boletin_envio_n';         // contador «Envío N°» del pie
const MAX_PARA = 3;
const MAX_CC = 7;
const MAX_TOTAL = 10;
const MAX_HTML = 1600000;      // ~1.6 MB (el boletín V17 pesa ~250 KB)
const MAX_PDF_B64 = 3400000;   // ~2.5 MB binarios: deja holgura bajo el límite de 4.5 MB de Vercel
const RE_CORREO = /^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]{2,}$/;

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

function parseCorreos(valor) {
  const v = String(valor || '').trim();
  if (!v) return [];
  return [...new Set(v.split(/[,;\s]+/).map(function (s) { return s.trim(); }).filter(Boolean))];
}

function claves() {
  const k = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
  return k ? { apikey: k, Authorization: `Bearer ${k}`, 'Content-Type': 'application/json' } : null;
}

/* Formato de los destinos: ≤3 en Para, ≤7 en Cc, 10 en total. Devuelve el error o null. */
function errorFormatoCorreos(para, cc) {
  if (para.length > MAX_PARA) return `Máximo ${MAX_PARA} correos en Para.`;
  if (cc.length > MAX_CC) return `Máximo ${MAX_CC} correos en Cc.`;
  if (para.length + cc.length > MAX_TOTAL) return `Máximo ${MAX_TOTAL} correos en total (${MAX_PARA} en Para y ${MAX_CC} en Cc).`;
  for (const c of para.concat(cc)) {
    if (c.length > 120 || !RE_CORREO.test(c)) return 'Correo inválido: ' + textoSeguro(c, 60);
  }
  return null;
}

function remitenteActual(adm) {
  return String(process.env.GMAIL_USER || (adm && adm.email) || 'Modulo VEA').trim();
}

function leerAuto(valor) {
  try {
    const a = JSON.parse(String(valor || 'null'));
    return a && typeof a === 'object' ? a : null;
  } catch (_) { return null; }
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

async function cargarPdfGuardado(id) {
  const k = claves();
  if (!k || !id) return { pdf: '', tienePdf: false };
  try {
    const r = await fetch(`${SUPABASE_URL}/rest/v1/vea_boletines?select=pdf_base64,tiene_pdf&id=eq.${id}&limit=1`, {
      headers: k, cache: 'no-store'
    });
    const filas = r.ok ? await r.json().catch(() => []) : [];
    const f = Array.isArray(filas) && filas.length ? filas[0] : null;
    const pdf = f ? String(f.pdf_base64 || '').replace(/\s+/g, '') : '';
    return { pdf, tienePdf: Boolean(f && f.tiene_pdf) || !!pdf };
  } catch (_) {
    return { pdf: '', tienePdf: false };
  }
}

async function ultimoBoletin() {
  const r = await consultar('vea_boletines?select=id,anio,se,tiene_pdf,pdf_base64,creado_en&order=anio.desc,se.desc&limit=1');
  if (r.error || !Array.isArray(r.datos) || !r.datos.length) return null;
  return r.datos[0];
}

/**
 * Envía la circular aprobada a Para + Cc (un solo mensaje: todos ven las
 * cabeceras). Regla de tamaño: PDF ≤ 700 KB adjunto; si pesa más se guarda
 * (si hace falta) y va el botón «Descargar PDF» — el texto SIEMPRE llega.
 */
async function enviarCircular(o) {
  const enlace = `${BASE_URL}/boletines/${o.id}`;
  const pdf = o.pdf || '';
  const bytes = pdf ? Math.ceil(pdf.length * 3 / 4) : 0;
  const hayPdf = !!pdf || !!o.tienePdf;
  const adjuntar = !!pdf && bytes <= LIMITE_ADJUNTO_BYTES;
  const boton = !adjuntar && hayPdf;
  if (pdf && !adjuntar && o.id) {
    // Se asegura de que el PDF exista en el servidor para que el botón no 404.
    await marcarEnvio(o.id, { pdf_base64: pdf, tiene_pdf: true });
  }
  const n = (Number(o.envioN) || 0) + 1;
  const nombre = nombreArchivo(o.se, o.anio);
  const html = plantillaCircular({
    se: o.se, anio: o.anio, enlace, hayPdf, adjuntar, boton,
    pesoBytes: bytes,
    pdfUrl: `${BASE_URL}/api/boletines?i=${o.id}&pdf=1`,
    nombre, remitente: o.remitente, envioN: n
  });
  const adjuntos = adjuntar ? [{ nombre, base64: pdf, tipo: 'application/pdf' }] : [];
  const destinos = o.para.concat(o.cc);
  const r = await enviarCorreo({ para: o.para, cc: o.cc, asunto: asuntoCircular(o.se, o.anio), html, adjuntos });
  if (r.ok) {
    await guardarConfig({ [CLAVE_ENVIO_N]: String(n) });
    return { ok: true, adjunto: adjuntar, boton, enlace, destinos };
  }
  const detalle = textoSeguro(String(r.detalle || r.error || 'error'), 80);
  return {
    ok: false, adjunto: false, boton: false, enlace, destinos: [],
    fallos: [{ correo: destinos.join(', '), error: detalle }]
  };
}

/* ============================ SOLO ADM ============================ */
async function atenderAdm(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');

  if (req.method !== 'GET' && req.method !== 'POST') {
    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  // Sesión ADM obligatoria — falla cerrada (mismo criterio que /api/auth/log).
  const adm = await admActivo(req);
  if (!adm) return res.status(401).json({ error: 'Se requiere sesión de administrador' });

  if (req.method === 'GET') {
    const lectura = await leerConfig([CLAVE_CORREO, CLAVE_CORREO_CC, CLAVE_CORREO_CAMBIO, CLAVE_AUTO, CLAVE_ENVIO_N]);
    if (lectura.error && !lectura.cfg) return res.status(502).json({ error: lectura.error });
    const cfg = lectura.cfg || {};
    const auto = leerAuto(cfg[CLAVE_AUTO]);
    return res.status(200).json({
      correo: cfg[CLAVE_CORREO] || '',
      correoCc: cfg[CLAVE_CORREO_CC] || '',
      correoCambio: cfg[CLAVE_CORREO_CAMBIO] || '',
      auto: auto,
      autoProximo: proximoEnvioTexto(auto)
    });
  }

  let body;
  try {
    body = JSON.parse(typeof req.body === 'string' ? req.body : (req.body ? JSON.stringify(req.body) : '{}'));
  } catch (_) {
    return res.status(400).json({ error: 'Cuerpo inválido.' });
  }
  const accion = String(body.accion || '');

  /* ---------- guardar los destinos (Para + Cc) ---------- */
  if (accion === 'guardar_correo') {
    const para = parseCorreos(body.correo);
    const cc = parseCorreos(body.correoCc);
    const error = errorFormatoCorreos(para, cc);
    if (error) return res.status(400).json({ error });
    const guardado = await guardarConfig({
      [CLAVE_CORREO]: para.join(', '),
      [CLAVE_CORREO_CC]: cc.join(', '),
      [CLAVE_CORREO_CAMBIO]: `${textoSeguro(adm.email || '', 80)} · ${new Date().toISOString()}`
    });
    if (!guardado) return res.status(502).json({ error: 'No se pudo guardar la configuración.' });
    return res.status(200).json({ ok: true, correo: para.join(', '), correoCc: cc.join(', ') });
  }

  /* ---------- programación del envío automático ---------- */
  if (accion === 'guardar_auto') {
    const dia = Number(body.dia);
    const hora = String(body.hora || '');
    if (!Number.isInteger(dia) || dia < 0 || dia > 6) return res.status(400).json({ error: 'Día inválido (0 = domingo … 6 = sábado).' });
    if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(hora)) return res.status(400).json({ error: 'Hora inválida (formato HH:MM, hora de Perú).' });

    const lectura = await leerConfig([CLAVE_AUTO, CLAVE_CORREO, CLAVE_CORREO_CC]);
    if (lectura.error && !lectura.cfg) return res.status(502).json({ error: lectura.error });
    const cfg = lectura.cfg || {};
    const previo = leerAuto(cfg[CLAVE_AUTO]);

    const cambios = {};
    if (typeof body.correoCc === 'string') {
      const para = parseCorreos(cfg[CLAVE_CORREO]);
      const cc = parseCorreos(body.correoCc);
      const error = errorFormatoCorreos(para, cc);
      if (error) return res.status(400).json({ error });
      cambios[CLAVE_CORREO_CC] = cc.join(', ');
    }
    const auto = { activo: body.activo === true, dia, hora };
    if (previo && previo.ultimo) auto.ultimo = previo.ultimo;
    cambios[CLAVE_AUTO] = JSON.stringify(auto);
    const guardado = await guardarConfig(cambios);
    if (!guardado) return res.status(502).json({ error: 'No se pudo guardar la programación.' });
    return res.status(200).json({ ok: true, auto, autoProximo: proximoEnvioTexto(auto) });
  }

  /* ---------- enviar prueba (circular real al último publicado) ---------- */
  if (accion === 'enviar_prueba') {
    const lectura = await leerConfig([CLAVE_CORREO, CLAVE_CORREO_CC, CLAVE_ENVIO_N]);
    if (lectura.error && !lectura.cfg) return res.status(502).json({ error: lectura.error });
    const cfg = lectura.cfg || {};
    const para = parseCorreos(cfg[CLAVE_CORREO]);
    const cc = parseCorreos(cfg[CLAVE_CORREO_CC]);
    if (!para.length) return res.status(400).json({ error: 'Sin correo en Para: guarde los destinos antes de enviar la prueba.' });

    const fila = await ultimoBoletin();
    if (!fila) return res.status(400).json({ error: 'Publique al menos un boletín: la prueba usa el último publicado.' });
    let pdf = String(fila.pdf_base64 || '').replace(/\s+/g, '');
    if (!pdf) {
      const g = await cargarPdfGuardado(Number(fila.id));
      pdf = g.pdf;
    }
    const r = await enviarCircular({
      para, cc,
      anio: Number(fila.anio), se: Number(fila.se), id: Number(fila.id),
      pdf: pdf || null, tienePdf: !!fila.tiene_pdf || !!pdf,
      envioN: cfg[CLAVE_ENVIO_N], remitente: remitenteActual(adm)
    });
    if (!r.ok) return res.status(502).json({ ok: false, error: 'No se pudo enviar la prueba: ' + (r.fallos[0] ? r.fallos[0].error : 'error') });
    return res.status(200).json({ ok: true, enviado: true, adjunto: r.adjunto, boton: r.boton, destinos: r.destinos, enlace: r.enlace });
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

    // El envío exige los destinos Para configurados (editable en este mismo panel).
    let para = [];
    let cc = [];
    let envioN = null;
    if (enviar) {
      const lectura = await leerConfig([CLAVE_CORREO, CLAVE_CORREO_CC, CLAVE_ENVIO_N]);
      if (lectura.error && !lectura.cfg) return res.status(502).json({ error: lectura.error });
      const cfg = lectura.cfg || {};
      para = parseCorreos(cfg[CLAVE_CORREO]);
      cc = parseCorreos(cfg[CLAVE_CORREO_CC]);
      envioN = cfg[CLAVE_ENVIO_N];
      if (!para.length) {
        return res.status(400).json({ error: 'Sin correo destino (Para): guarde los destinatarios antes de enviar.' });
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

    const respuesta = { ok: true, id, enlace: `${BASE_URL}/boletines/${id}`, enviado: false, adjunto: false, boton: false };

    if (enviar) {
      let pdfEfectivo = pdf;
      let tienePdf = !!pdf;
      if (!pdfEfectivo) {
        const g = await cargarPdfGuardado(id);
        pdfEfectivo = g.pdf;
        tienePdf = g.tienePdf;
      }
      const r = await enviarCircular({
        para, cc, anio, se, id,
        pdf: pdfEfectivo || null, tienePdf,
        envioN, remitente: remitenteActual(adm)
      });
      respuesta.enviado = r.ok;
      respuesta.destinos = r.destinos;
      respuesta.fallos = r.fallos || [];
      respuesta.adjunto = r.adjunto;
      respuesta.boton = r.boton;
      if (r.ok) respuesta.enlace = r.enlace;
      await marcarEnvio(id, {
        correo_destino: textoSeguro(para.concat(cc).join(', '), 300),
        enviado: r.ok,
        enviado_detalle: textoSeguro(
          r.ok
            ? `enviado a ${r.destinos.join(', ')}${r.adjunto ? ' (PDF adjunto)' : (r.boton ? ' (botón de descarga)' : '')}`
            : `falló: ${(r.fallos[0] ? r.fallos[0].error : 'sin detalle')}`,
          500
        )
      });
      if (!r.ok) {
        return res.status(502).json({
          ok: false, publicado: true, id, enlace: respuesta.enlace, enviado: false, adjunto: false,
          error: 'Boletín publicado pero el correo no pudo enviarse: ' + (r.fallos[0] ? r.fallos[0].error : 'sin detalle') +
            '. Verifique la configuración de correo en Vercel.'
        });
      }
    }

    return res.status(200).json(respuesta);
  }

  return res.status(400).json({ error: 'Acción no reconocida.' });
}

/* ====================== CRON · ENVÍO AUTOMÁTICO ====================== */
async function atenderAuto(req, res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  // Falla cerrada: sin CRON_SECRET configurado o sin la cabecera exacta, nada.
  const secreto = String(process.env.CRON_SECRET || '').trim();
  const auth = String((req.headers && req.headers.authorization) || '');
  if (!secreto) return res.status(503).json({ error: 'CRON_SECRET no configurado en Vercel.' });
  if (auth !== 'Bearer ' + secreto) return res.status(401).json({ error: 'Cron no autorizado' });

  const lectura = await leerConfig([CLAVE_AUTO, CLAVE_CORREO, CLAVE_CORREO_CC, CLAVE_ENVIO_N]);
  if (lectura.error && !lectura.cfg) return res.status(502).json({ error: lectura.error });
  const cfg = lectura.cfg || {};
  const auto = leerAuto(cfg[CLAVE_AUTO]);
  if (!auto || auto.activo !== true) return res.status(200).json({ ok: true, estado: 'inactivo' });

  const ahora = new Date();
  if (!listoParaDisparar(auto, ahora)) return res.status(200).json({ ok: true, estado: 'fuera_de_programacion' });
  const iso = ahora.toISOString();
  if (auto.ultimo && auto.ultimo.iso && (Date.now() - Date.parse(auto.ultimo.iso)) < 12 * 3600 * 1000) {
    // Ya se disparó en esta ventana (el cron corre cada 15 minutos).
    return res.status(200).json({ ok: true, estado: 'ya_disparado', ultimo: auto.ultimo });
  }

  const para = parseCorreos(cfg[CLAVE_CORREO]);
  const cc = parseCorreos(cfg[CLAVE_CORREO_CC]);
  const guardarUltimo = async function (ultimo) {
    await guardarConfig({ [CLAVE_AUTO]: JSON.stringify(Object.assign({}, auto, { ultimo })) });
  };

  if (!para.length) {
    await guardarUltimo({ iso, tipo: 'error', estado: 'sin_correos', detalle: 'Sin correo Para configurado' });
    return res.status(200).json({ ok: false, estado: 'sin_correos' });
  }

  const remitente = remitenteActual(null);
  const fila = await ultimoBoletin();
  const fresco = Boolean(fila && fila.creado_en && (Date.now() - Date.parse(fila.creado_en)) <= 14 * 86400 * 1000);
  let ok = false;
  let tipo = 'recordatorio';
  let detalle = '';

  if (fresco) {
    tipo = 'circular';
    const pdf = String(fila.pdf_base64 || '').replace(/\s+/g, '');
    const r = await enviarCircular({
      para, cc,
      anio: Number(fila.anio), se: Number(fila.se), id: Number(fila.id),
      pdf: pdf || null, tienePdf: !!fila.tiene_pdf || !!pdf,
      envioN: cfg[CLAVE_ENVIO_N], remitente
    });
    ok = r.ok;
    detalle = r.ok
      ? `circular S.E. ${fila.se}-${fila.anio} a ${r.destinos.join(', ')}${r.adjunto ? ' (adjunto)' : (r.boton ? ' (botón)' : '')}`
      : (r.fallos[0] ? r.fallos[0].error : 'error de envío');
  } else {
    const n = (Number(cfg[CLAVE_ENVIO_N]) || 0) + 1;
    const html = plantillaRecordatorio({ remitente, envioN: n, enlaceListado: `${BASE_URL}/boletines` });
    const r = await enviarCorreo({
      para, cc,
      asunto: 'Recordatorio · Boletín epidemiológico · Hospital de Ventanilla',
      html
    });
    ok = r.ok;
    if (ok) await guardarConfig({ [CLAVE_ENVIO_N]: String(n) });
    detalle = ok
      ? `recordatorio a ${para.concat(cc).join(', ')} (sin boletín publicado)`
      : textoSeguro(String(r.detalle || r.error || 'error'), 80);
  }

  await guardarUltimo({ iso, tipo, estado: ok ? 'enviado' : 'fallido', detalle: textoSeguro(detalle, 200) });
  return res.status(200).json({ ok, estado: tipo, detalle });
}

module.exports = async function handler(req, res) {
  if (String(req.query && req.query.auto != null ? req.query.auto : '') === '1') return atenderAuto(req, res);

  const esAdm = req.method === 'POST' || (req.query && String(req.query.adm || '') === '1');
  if (esAdm) return atenderAdm(req, res);

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
