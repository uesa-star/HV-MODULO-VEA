#!/usr/bin/env node
/**
 * Verificación de seguridad del módulo VEA (vigilancia anti-ataque).
 *
 * Comprueba en producción que:
 *   1. /api/vea-sync responde 401 sin sesión ADM (no quedó abierto).
 *   2. /api/vea-data, /api/alerts y /api/auth/me responden 401 sin sesión.
 *   3. / redirige a /login.html y /login.html carga.
 *   4. La llave pública NO puede leer tablas de vigilancia (privilegios revocados).
 *   5. La función de firma vea_firma_tabla sigue disponible (el módulo la usa).
 *   6. Cabeceras de seguridad presentes (HSTS, nosniff, frame, CSP).
 *
 * Sale con código 1 si algo falla → GitHub Actions avisa por correo.
 * Uso:  node scripts/verificar_seguridad.mjs
 *       BASE_URL=https://... node scripts/verificar_seguridad.mjs
 */
const BASE = (process.env.BASE_URL || 'https://vigilancia-epidemiologica-ecru.vercel.app').replace(/\/+$/, '');
const SUPA = 'https://qtsfkoasfoaovadilwgk.supabase.co';
// Lave publishable: es PÚBLICA (viene en el HTML del módulo). Si Supabase la
// rota, definir VEA_PUBLISHABLE_KEY en el entorno.
const PUB = process.env.VEA_PUBLISHABLE_KEY || 'sb_publishable_uzdpUnVRYRQY3lROvtNwiw_qa4iyJwj';

const resultados = [];
async function check(nombre, fn) {
  try {
    const detalle = await fn();
    resultados.push({ ok: true, nombre, detalle: detalle || '' });
    console.log(`PASS  ${nombre}${detalle ? ' — ' + detalle : ''}`);
  } catch (e) {
    resultados.push({ ok: false, nombre, detalle: String(e.message || e) });
    console.log(`FALLO ${nombre} — ${e.message || e}`);
  }
}
const espera = (cond, msg) => { if (!cond) throw new Error(msg); };

async function pedir(url, init = {}) {
  const r = await fetch(url, { redirect: 'manual', ...init });
  const texto = await r.text().catch(() => '');
  return { r, texto };
}

await check('POST /api/vea-sync sin sesión → 401', async () => {
  const { r, texto } = await pedir(`${BASE}/api/vea-sync`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tabla: 'edas', registros: [] })
  });
  espera(r.status === 401, `devolvió ${r.status}: ${texto.slice(0, 120)}`);
  return '401';
});

for (const ruta of ['/api/vea-data?table=edas&offset=0&limit=1', '/api/alerts', '/api/auth/me']) {
  await check(`GET ${ruta.split('?')[0]} sin sesión → 401`, async () => {
    const { r, texto } = await pedir(`${BASE}${ruta}`);
    espera(r.status === 401, `devolvió ${r.status}: ${texto.slice(0, 120)}`);
    return '401';
  });
}

await check('GET / sin sesión → 302 a /login.html', async () => {
  const { r } = await pedir(`${BASE}/`);
  const loc = r.headers.get('location') || '';
  espera(r.status === 302 && loc.includes('/login.html'), `devolvió ${r.status} → ${loc}`);
  return '302 → /login.html';
});

await check('GET /login.html → 200 con aviso de recuperación', async () => {
  const { r, texto } = await pedir(`${BASE}/login.html`);
  espera(r.status === 200, `devolvió ${r.status}`);
  espera(texto.includes('avisoEnviado') && texto.includes('3 minutos'), 'falta el aviso de código enviado');
  return '200';
});

await check('Cabeceras de seguridad en /', async () => {
  const { r } = await pedir(`${BASE}/`);
  const h = r.headers;
  const faltan = [];
  if (!h.get('x-content-type-options')) faltan.push('X-Content-Type-Options');
  if (!h.get('x-frame-options')) faltan.push('X-Frame-Options');
  if (!h.get('strict-transport-security')) faltan.push('Strict-Transport-Security');
  if (!h.get('content-security-policy')) faltan.push('Content-Security-Policy');
  espera(!faltan.length, `faltan: ${faltan.join(', ')}`);
  return 'todas presentes';
});

await check('Llave pública NO lee tablas de vigilancia', async () => {
  const faltan = [];
  for (const t of ['edas', 'iras', 'febriles', 'individual', 'soat', 'tbc', 'vih']) {
    const r = await fetch(`${SUPA}/rest/v1/${t}?select=*&limit=1`, {
      headers: { apikey: PUB, Authorization: `Bearer ${PUB}` }
    });
    if (r.status !== 401 && r.status !== 403) faltan.push(`${t}(${r.status})`);
  }
  espera(!faltan.length, `lectura permitida en: ${faltan.join(', ')}`);
  return 'todas denegadas (401)';
});

await check('Firma vea_firma_tabla disponible para el módulo', async () => {
  const r = await fetch(`${SUPA}/rest/v1/rpc/vea_firma_tabla`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', apikey: PUB, Authorization: `Bearer ${PUB}` },
    body: JSON.stringify({ p_tabla: 'edas' })
  });
  const t = await r.text();
  espera(r.status === 200, `devolvió ${r.status}: ${t.slice(0, 120)}`);
  return `200 (${t.slice(0, 30)})`;
});

const fallidos = resultados.filter(x => !x.ok).length;
console.log(`\n${resultados.length - fallidos}/${resultados.length} verificaciones OK`);
if (fallidos) {
  console.error(`${fallidos} FALLARON: revisar si alguien cambió código, permisos o cabeceras.`);
  process.exit(1);
}
