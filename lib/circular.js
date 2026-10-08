/**
 * VEA — Circular del boletín epidemiológico (texto aprobado por la Unidad de
 * Epidemiología y Salud Ambiental):
 *   · asunto corto: "Boletín S.E. 39-2026 · Hospital de Ventanilla"
 *   · saludo dinámico por hora de Perú (GMT-5): días / tardes / noches
 *   · PDF ≤ 700 KB va adjunto; si pesa más, botón «Descargar PDF»
 *     (Gmail oculta el cuerpo cuando el adjunto hace el mensaje muy pesado)
 *   · pie monoespaciado con N° de envío, remitente, fecha (GMT-5) y módulo
 */
const LIMITE_ADJUNTO_BYTES = 700 * 1024;
const DIAS = ['domingo', 'lunes', 'martes', 'miércoles', 'jueves', 'viernes', 'sábado'];
const DOW = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

function partesLima(d) {
  const f = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'America/Lima', weekday: 'short', day: '2-digit',
    month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false
  });
  const p = {};
  f.formatToParts(d).forEach(function (x) { if (x.type !== 'literal') p[x.type] = x.value; });
  const idx = Math.max(0, DOW.indexOf(p.weekday));
  return {
    dow: idx,
    dia: DIAS[idx],
    hora: Number(p.hour) % 24, // "24" aparece a medianoche en algunos ICU
    minuto: Number(p.minute),
    dd: p.day, mes: p.month, anio: p.year
  };
}

function saludoPorHora(hora) {
  if (hora >= 6 && hora < 12) return 'Buenos días:';
  if (hora >= 12 && hora < 19) return 'Buenas tardes:';
  return 'Buenas noches:';
}

function asuntoCircular(se, anio) {
  return `Boletín S.E. ${String(se).padStart(2, '0')}-${anio} · Hospital de Ventanilla`;
}

function nombreArchivo(se, anio) {
  return `Boletin_Epidemiologico_SE${String(se).padStart(2, '0')}_${anio}.pdf`;
}

function pesoLegible(bytes) {
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + ' MB';
  return Math.max(1, Math.round(bytes / 1024)) + ' KB';
}

/**
 * ¿Corresponde disparar ya? { activo, dia (0=domingo), hora:'HH:MM' }.
 * El cron corre cada 15 minutos; la ventana es desde HH:MM hasta el final
 * de la hora (el guardado de 12 h evita el doble envío).
 */
function listoParaDisparar(auto, d) {
  if (!auto || !auto.activo || auto.dia == null || !/^\d{2}:\d{2}$/.test(String(auto.hora || ''))) return false;
  const p = partesLima(d || new Date());
  const hh = Number(String(auto.hora).slice(0, 2));
  const mm = Number(String(auto.hora).slice(3, 5));
  return p.dow === Number(auto.dia) && p.hora === hh && p.minuto >= mm;
}

function proximoEnvioTexto(auto) {
  if (!auto || !auto.activo || auto.dia == null || !/^\d{2}:\d{2}$/.test(String(auto.hora || ''))) return '';
  const hh = Number(String(auto.hora).slice(0, 2));
  const mm = Number(String(auto.hora).slice(3, 5));
  const dow = Number(auto.dia);
  for (let off = 0; off < 8; off++) {
    const p = partesLima(new Date(Date.now() + off * 86400000));
    if (p.dow !== dow) continue;
    if (off === 0 && (p.hora > hh || (p.hora === hh && p.minuto >= mm))) continue;
    const dia = DIAS[dow];
    return `${dia.charAt(0).toUpperCase() + dia.slice(1)} ${p.dd}/${p.mes}/${p.anio} ${auto.hora} (hora Perú)`;
  }
  return '';
}

/* ==================== plantilla HTML (circular aprobada) ==================== */
function plantillaCircular(o) {
  const sse = String(o.se).padStart(2, '0');
  const p = partesLima(new Date());
  const fecha = `${p.dd}/${p.mes}/${p.anio}`;
  const saludo = saludoPorHora(p.hora);
  const parrafo = o.hayPdf
    ? `Se envía y adjunta el PDF del Boletín Epidemiológico de la S.E. ${sse} · ${o.anio}, para conocimiento y difusión en los diversos puntos, jefaturas de servicios del hospital, así como para su publicación en redes sociales cuando corresponda.`
    : `Se envía el Boletín Epidemiológico de la S.E. ${sse} · ${o.anio}, para conocimiento y difusión en los diversos puntos, jefaturas de servicios del hospital, así como para su publicación en redes sociales cuando corresponda.`;
  let bloqueArchivo = '';
  if (o.adjuntar) {
    bloqueArchivo = `<p style="font-size:14.5px;line-height:1.75;color:#0f172a;margin:0 0 14px">Se adjunta el archivo: ${o.nombre}</p>`;
  } else if (o.boton) {
    bloqueArchivo = `<p style="font-size:14.5px;line-height:1.75;color:#334155;margin:0 0 14px">Descargar el PDF (${pesoLegible(o.pesoBytes || 0)}): <a href="${o.pdfUrl}" style="display:inline-block;background:#059669;color:#ffffff;text-decoration:none;font-weight:bold;padding:8px 16px;border-radius:6px;font-size:13.5px">Descargar PDF</a></p>`;
  }
  const pie = `Envío N° ${o.envioN} · ${o.remitente} · ${fecha} (GMT-5) · Módulo VEA.`;
  return `<!doctype html><html><body style="margin:0;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;color:#1e293b">
  <div style="max-width:620px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0">
    <div style="background:#0056ac;padding:18px 24px">
      <div style="color:#ffffff;font-size:13px;letter-spacing:1px">HOSPITAL DE VENTANILLA · UNIDAD DE EPIDEMIOLOGÍA Y SALUD AMBIENTAL</div>
      <div style="color:#ffffff;font-size:19px;font-weight:bold;margin-top:4px">Boletín epidemiológico — S.E. ${sse} · ${o.anio}</div>
    </div>
    <div style="padding:24px">
      <p style="font-size:14.5px;line-height:1.75;color:#0f172a;font-weight:bold;margin:0 0 14px">${saludo}</p>
      <p style="font-size:14.5px;line-height:1.75;color:#334155;margin:0 0 14px">${parrafo}</p>
      ${bloqueArchivo}
      <p style="font-size:14.5px;line-height:1.75;color:#334155;margin:0 0 14px">Ver en línea: <a href="${o.enlace}" style="color:#0056ac;word-break:break-all">${o.enlace}</a></p>
      <p style="font-size:14.5px;line-height:1.75;color:#0f172a;margin:0">Atentamente,<br>Unidad de Epidemiología y Salud Ambiental — Hospital de Ventanilla</p>
      <div style="border-top:1px solid #e2e8f0;margin-top:8px;padding-top:14px;font-size:12px;color:#94a3b8;font-family:Consolas,Menlo,monospace">${pie}</div>
    </div>
  </div>
</body></html>`;
}

/* Recordatorio automático cuando esa semana no hay boletín publicado. */
function plantillaRecordatorio(o) {
  const p = partesLima(new Date());
  const fecha = `${p.dd}/${p.mes}/${p.anio}`;
  const saludo = saludoPorHora(p.hora);
  const pie = `Envío N° ${o.envioN} · ${o.remitente} · ${fecha} (GMT-5) · Módulo VEA.`;
  return `<!doctype html><html><body style="margin:0;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;color:#1e293b">
  <div style="max-width:620px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0">
    <div style="background:#0056ac;padding:18px 24px">
      <div style="color:#ffffff;font-size:13px;letter-spacing:1px">HOSPITAL DE VENTANILLA · UNIDAD DE EPIDEMIOLOGÍA Y SALUD AMBIENTAL</div>
      <div style="color:#ffffff;font-size:19px;font-weight:bold;margin-top:4px">Boletín epidemiológico — recordatorio de publicación</div>
    </div>
    <div style="padding:24px">
      <p style="font-size:14.5px;line-height:1.75;color:#0f172a;font-weight:bold;margin:0 0 14px">${saludo}</p>
      <p style="font-size:14.5px;line-height:1.75;color:#334155;margin:0 0 14px">Recordatorio automático del Módulo VEA: hasta este momento no se publica el boletín epidemiológico de la semana en el listado público. Publíquelo desde el panel de administración (ADM → Boletín) para que la circular con el PDF se envíe a la lista de destinatarios.</p>
      <p style="font-size:14.5px;line-height:1.75;color:#334155;margin:0 0 14px">Listado público: <a href="${o.enlaceListado}" style="color:#0056ac;word-break:break-all">${o.enlaceListado}</a></p>
      <p style="font-size:14.5px;line-height:1.75;color:#0f172a;margin:0">Atentamente,<br>Unidad de Epidemiología y Salud Ambiental — Hospital de Ventanilla</p>
      <div style="border-top:1px solid #e2e8f0;margin-top:8px;padding-top:14px;font-size:12px;color:#94a3b8;font-family:Consolas,Menlo,monospace">${pie}</div>
    </div>
  </div>
</body></html>`;
}

module.exports = {
  LIMITE_ADJUNTO_BYTES,
  partesLima,
  saludoPorHora,
  asuntoCircular,
  nombreArchivo,
  pesoLegible,
  listoParaDisparar,
  proximoEnvioTexto,
  plantillaCircular,
  plantillaRecordatorio
};
